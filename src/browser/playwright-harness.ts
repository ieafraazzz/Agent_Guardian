import { Browser, BrowserContext, chromium, Page, Route } from 'playwright';
import { Decision } from '../core/types';
import { SessionPolicy } from '../types';
import { BrowserAction, BrowserGuardian, BrowserObservation } from './guardian';
import { CrossSurfaceStore } from './cross-surface-store';

export interface PlaywrightHarnessOptions {
  storagePath: string;
  sessionId: string;
  trustedOrigins?: string[];
  sessionPolicy?: SessionPolicy;
  headless?: boolean;
  approvalHandler?: (decision: Decision, action: BrowserAction) => boolean | Promise<boolean>;
}

export class GuardedBrowserHarness {
  private browser?: Browser;
  private context?: BrowserContext;
  private page?: Page;
  private readonly guardian: BrowserGuardian;
  private readonly networkDestinations = new Set<string>();

  constructor(private readonly options: PlaywrightHarnessOptions) {
    this.guardian = new BrowserGuardian(new CrossSurfaceStore(options.storagePath), {
      trustedOrigins: options.trustedOrigins,
      sessionPolicy: options.sessionPolicy
    });
  }

  async start(): Promise<void> {
    this.browser = await chromium.launch({ headless: this.options.headless ?? true });
    this.context = await this.browser.newContext({ acceptDownloads: false });
    this.page = await this.context.newPage();
    this.page.on('request', request => {
      try { this.networkDestinations.add(new URL(request.url()).origin); } catch { /* Ignore non-URL schemes. */ }
    });
    await this.page.route('**/*', route => this.guardNetworkRoute(route));
  }

  async navigate(url: string): Promise<Decision> {
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type: 'navigate',
      destination: url,
      capability: 'BROWSER_NAVIGATE'
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) await this.requirePage().goto(url, { waitUntil: 'domcontentloaded' });
    return decision;
  }

  async observe(): Promise<{ observation: BrowserObservation; evidenceCount: number }> {
    const page = this.requirePage();
    const main = await page.evaluate(() => ({
      title: document.title,
      visibleText: document.body?.innerText || '',
      agentText: document.body?.textContent || '',
      links: Array.from(document.querySelectorAll('a[href]')).map(link => ({
        text: (link.textContent || '').trim(),
        href: (link as HTMLAnchorElement).href
      })),
      forms: Array.from(document.forms).map(form => ({
        action: form.action,
        method: form.method,
        fields: Array.from(form.elements).map(element => (element as HTMLInputElement).name).filter(Boolean)
      }))
    }));
    const frames: Array<{ url: string; visibleText: string }> = [];
    for (const frame of page.frames().filter(item => item !== page.mainFrame())) {
      try {
        frames.push({ url: frame.url(), visibleText: await frame.locator('body').innerText({ timeout: 1_000 }) });
      } catch {
        frames.push({ url: frame.url(), visibleText: '[frame unavailable]' });
      }
    }
    const observation: BrowserObservation = {
      sessionId: this.options.sessionId,
      url: page.url(),
      origin: new URL(page.url()).origin,
      title: main.title,
      visibleText: main.visibleText,
      agentText: main.agentText,
      frames,
      links: main.links,
      forms: main.forms,
      networkDestinations: Array.from(this.networkDestinations)
    };
    const result = this.guardian.observe(observation);
    return { observation, evidenceCount: result.evidence.length };
  }

  async fill(selector: string, value: string, labels: Array<'credential' | 'sensitive' | 'personal'> = []): Promise<Decision | undefined> {
    const page = this.requirePage();
    const element = page.locator(selector);
    const type = await element.getAttribute('type');
    const credential = type === 'password' || labels.includes('credential');
    if (credential) {
      const action: BrowserAction = {
        sessionId: this.options.sessionId,
        type: 'credential_entry',
        source: page.url(),
        destination: new URL(page.url()).origin,
        payload: { selector, value },
        dataLabels: ['credential', 'sensitive'],
        capability: 'BROWSER_CREDENTIAL_ENTRY'
      };
      const decision = this.guardian.gate(action);
      if (!(await this.mayProceed(decision, action))) return decision;
    }
    await element.fill(value);
    return undefined;
  }

  async submit(selector: string): Promise<Decision> {
    const page = this.requirePage();
    const form = page.locator(selector);
    const details = await form.evaluate(node => {
      const target = node as HTMLFormElement;
      return {
        action: target.action,
        method: target.method,
        values: Object.fromEntries(Array.from(target.elements)
          .filter(element => Boolean((element as HTMLInputElement).name))
          .map(element => {
            const field = element as HTMLInputElement;
            return [field.name, field.value] as [string, string];
          }))
      };
    });
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type: 'submit_form',
      source: page.url(),
      destination: details.action,
      payload: details,
      capability: 'BROWSER_SUBMIT_FORM'
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) {
      const response = page.waitForResponse(candidate =>
        candidate.url().startsWith(details.action) &&
        candidate.request().method().toLowerCase() === details.method.toLowerCase(),
      { timeout: 5_000 });
      await form.evaluate(node => (node as HTMLFormElement).submit());
      await response;
    }
    return decision;
  }

  async download(selector: string): Promise<Decision> {
    return this.gateClick(selector, 'download', 'BROWSER_DOWNLOAD');
  }

  async purchase(selector: string): Promise<Decision> {
    return this.gateClick(selector, 'purchase', 'BROWSER_PURCHASE');
  }

  async close(): Promise<void> {
    await this.context?.close();
    await this.browser?.close();
    this.page = undefined;
    this.context = undefined;
    this.browser = undefined;
  }

  private async guardNetworkRoute(route: Route): Promise<void> {
    const request = route.request();
    const method = request.method().toUpperCase();
    const guarded = !['GET', 'HEAD', 'OPTIONS'].includes(method) ||
      ['xhr', 'fetch', 'websocket'].includes(request.resourceType());
    if (!guarded) {
      await route.continue();
      return;
    }
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type: 'network_request',
      source: this.page?.url(),
      destination: request.url(),
      payload: { method, postData: request.postData() },
      capability: 'BROWSER_NETWORK_REQUEST'
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) await route.continue();
    else await route.abort('blockedbyclient');
  }

  private async gateClick(
    selector: string,
    type: 'download' | 'purchase',
    capability: string
  ): Promise<Decision> {
    const page = this.requirePage();
    const element = page.locator(selector);
    const href = await element.getAttribute('href');
    const destination = href ? new URL(href, page.url()).toString() : page.url();
    const action: BrowserAction = {
      sessionId: this.options.sessionId,
      type,
      source: page.url(),
      destination,
      payload: { selector, text: await element.innerText().catch(() => '') },
      capability
    };
    const decision = this.guardian.gate(action);
    if (await this.mayProceed(decision, action)) await element.click();
    return decision;
  }

  private async mayProceed(decision: Decision, action: BrowserAction): Promise<boolean> {
    if (decision.outcome === 'ALLOW') return true;
    if (decision.outcome === 'ASK' && this.options.approvalHandler) {
      const approved = await this.options.approvalHandler(decision, action);
      decision.userResponse = approved ? 'approve_once' : 'deny';
      return approved;
    }
    return false;
  }

  private requirePage(): Page {
    if (!this.page) throw new Error('Browser harness has not been started');
    return this.page;
  }
}

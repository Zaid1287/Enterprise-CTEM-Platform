import { exec, execSync } from "child_process";
import { promisify } from "util";
import { orchestratedFetch, type OrchestratorContext } from "./scanOrchestrator";

const execAsync  = promisify(exec);
const WHATWEB_BIN = (() => { try { return execSync("which whatweb 2>/dev/null", { timeout: 3000 }).toString().trim(); } catch { return ""; } })();

export interface DetectedTechnology {
  slug: string;
  name: string;
  category: string;
  version?: string;
  confidence: number;
  website?: string;
  cpe?: string;
  icon?: string;
  hosts?: string[];
}

interface HeaderPattern { name: string; re: RegExp; version?: number }
interface HtmlPattern   { re: RegExp; version?: number }
interface CookiePattern { re: RegExp; version?: number }
interface ScriptPattern { re: RegExp; version?: number }

interface Tech {
  slug: string; name: string; category: string;
  website?: string; cpe?: string; icon?: string;
  confidence: number;
  headers?:  HeaderPattern[];
  html?:     HtmlPattern[];
  cookies?:  CookiePattern[];
  scripts?:  ScriptPattern[];
}

function ver(m: RegExpMatchArray | null, g?: number): string | undefined {
  if (!m || g === undefined || !m[g]) return undefined;
  return m[g].trim().replace(/^v/, "");
}

const TECHS: Tech[] = [
  // ── Web Servers ─────────────────────────────────────────────────────
  {
    slug: "nginx", name: "Nginx", category: "Web Server",
    website: "https://nginx.org", cpe: "cpe:2.3:a:nginx:nginx", icon: "🌐", confidence: 100,
    headers: [{ name: "server", re: /nginx(?:\/(\d[\d.]+))?/i, version: 1 }],
  },
  {
    slug: "apache", name: "Apache HTTP Server", category: "Web Server",
    website: "https://httpd.apache.org", cpe: "cpe:2.3:a:apache:http_server", icon: "🪶", confidence: 100,
    headers: [{ name: "server", re: /Apache(?:\/(\d[\d.]+))?/i, version: 1 }],
  },
  {
    slug: "iis", name: "Microsoft IIS", category: "Web Server",
    website: "https://www.iis.net", cpe: "cpe:2.3:a:microsoft:iis", icon: "🪟", confidence: 100,
    headers: [{ name: "server", re: /Microsoft-IIS(?:\/(\d[\d.]+))?/i, version: 1 }],
  },
  {
    slug: "cloudflare-server", name: "Cloudflare", category: "CDN",
    website: "https://www.cloudflare.com", icon: "☁️", confidence: 100,
    headers: [{ name: "server", re: /cloudflare/i }],
  },
  {
    slug: "openresty", name: "OpenResty", category: "Web Server",
    website: "https://openresty.org", icon: "🌐", confidence: 100,
    headers: [{ name: "server", re: /openresty(?:\/(\d[\d.]+))?/i, version: 1 }],
  },
  {
    slug: "litespeed", name: "LiteSpeed", category: "Web Server",
    website: "https://www.litespeedtech.com", icon: "⚡", confidence: 100,
    headers: [{ name: "server", re: /LiteSpeed/i }],
  },
  {
    slug: "caddy", name: "Caddy", category: "Web Server",
    website: "https://caddyserver.com", icon: "🌐", confidence: 100,
    headers: [{ name: "server", re: /Caddy/i }],
  },
  {
    slug: "gunicorn", name: "Gunicorn", category: "Web Server",
    website: "https://gunicorn.org", icon: "🦄", confidence: 100,
    headers: [{ name: "server", re: /gunicorn(?:\/(\d[\d.]+))?/i, version: 1 }],
  },
  {
    slug: "vercel", name: "Vercel", category: "PaaS",
    website: "https://vercel.com", icon: "▲", confidence: 100,
    headers: [
      { name: "x-vercel-id", re: /.+/ },
      { name: "server", re: /Vercel/i },
    ],
  },
  {
    slug: "netlify", name: "Netlify", category: "PaaS",
    website: "https://netlify.com", icon: "🌿", confidence: 100,
    headers: [{ name: "x-nf-request-id", re: /.+/ }],
  },
  {
    slug: "heroku", name: "Heroku", category: "PaaS",
    website: "https://heroku.com", icon: "💜", confidence: 90,
    headers: [{ name: "via", re: /heroku/i }],
  },

  // ── Backend / Language ───────────────────────────────────────────────
  {
    slug: "php", name: "PHP", category: "Programming Language",
    website: "https://www.php.net", cpe: "cpe:2.3:a:php:php", icon: "🐘", confidence: 100,
    headers: [{ name: "x-powered-by", re: /PHP(?:\/(\d[\d.]+))?/i, version: 1 }],
    cookies: [{ re: /PHPSESSID/i }],
  },
  {
    slug: "express", name: "Express", category: "Web Framework",
    website: "https://expressjs.com", icon: "🚂", confidence: 90,
    headers: [{ name: "x-powered-by", re: /Express/i }],
  },
  {
    slug: "aspnet", name: "ASP.NET", category: "Web Framework",
    website: "https://dotnet.microsoft.com", cpe: "cpe:2.3:a:microsoft:asp.net", icon: "🪟", confidence: 100,
    headers: [
      { name: "x-powered-by", re: /ASP\.NET/i },
      { name: "x-aspnet-version", re: /(\d[\d.]+)/, version: 1 },
    ],
  },
  {
    slug: "java-servlet", name: "Java Servlet", category: "Programming Language",
    website: "https://www.oracle.com/java", icon: "☕", confidence: 80,
    cookies: [{ re: /JSESSIONID/i }],
    headers: [{ name: "x-powered-by", re: /Servlet/i }],
  },
  {
    slug: "python-django", name: "Django", category: "Web Framework",
    website: "https://www.djangoproject.com", icon: "🐍", confidence: 80,
    cookies: [{ re: /csrfmiddlewaretoken/i }],
    html: [{ re: /csrfmiddlewaretoken/i }],
  },
  {
    slug: "ruby-rails", name: "Ruby on Rails", category: "Web Framework",
    website: "https://rubyonrails.org", icon: "💎", confidence: 80,
    headers: [
      { name: "x-runtime", re: /\d+\.\d+/ },
      { name: "x-powered-by", re: /Phusion/i },
    ],
    cookies: [{ re: /_session_id/i }],
  },

  // ── CMS ──────────────────────────────────────────────────────────────
  {
    slug: "wordpress", name: "WordPress", category: "CMS",
    website: "https://wordpress.org", cpe: "cpe:2.3:a:wordpress:wordpress", icon: "📝", confidence: 100,
    html: [
      { re: /(?:wp-content|wp-includes)/i },
      { re: /<meta[^>]+generator[^>]+WordPress[^"']*["'](\d[\d.]+)/i, version: 1 },
    ],
    headers: [
      { name: "x-pingback", re: /.+/ },
      { name: "x-generator", re: /WordPress/i },
    ],
  },
  {
    slug: "drupal", name: "Drupal", category: "CMS",
    website: "https://www.drupal.org", cpe: "cpe:2.3:a:drupal:drupal", icon: "💧", confidence: 100,
    html: [{ re: /<meta[^>]+generator[^>]+Drupal[^"']*["'](\d[\d.]+)/i, version: 1 }],
    headers: [
      { name: "x-generator", re: /Drupal(?:\s+(\d+))?/i, version: 1 },
      { name: "x-drupal-cache", re: /.+/ },
    ],
  },
  {
    slug: "joomla", name: "Joomla", category: "CMS",
    website: "https://www.joomla.org", cpe: "cpe:2.3:a:joomla:joomla!", icon: "🌀", confidence: 100,
    html: [
      { re: /<meta[^>]+generator[^>]+Joomla/i },
      { re: /com_content/i },
    ],
  },
  {
    slug: "ghost", name: "Ghost", category: "CMS",
    website: "https://ghost.org", icon: "👻", confidence: 100,
    html: [{ re: /<meta[^>]+generator[^>]+Ghost[^"']*["'](\d[\d.]+)/i, version: 1 }],
    headers: [{ name: "x-ghost-cache-status", re: /.+/ }],
  },
  {
    slug: "shopify", name: "Shopify", category: "E-commerce",
    website: "https://www.shopify.com", icon: "🛍️", confidence: 100,
    html: [
      { re: /cdn\.shopify\.com/i },
      { re: /window\.Shopify\s*=/i },
      { re: /Shopify\.theme/i },
    ],
  },
  {
    slug: "squarespace", name: "Squarespace", category: "CMS",
    website: "https://www.squarespace.com", icon: "⬛", confidence: 100,
    html: [{ re: /squarespace\.com/i }],
    headers: [{ name: "server", re: /squarespace/i }],
  },
  {
    slug: "wix", name: "Wix", category: "CMS",
    website: "https://www.wix.com", icon: "✨", confidence: 100,
    html: [{ re: /wix\.com/i }],
    headers: [{ name: "x-wix-request-id", re: /.+/ }],
  },
  {
    slug: "webflow", name: "Webflow", category: "CMS",
    website: "https://webflow.com", icon: "🌊", confidence: 100,
    html: [{ re: /webflow\.js/i }],
    headers: [{ name: "x-wf-request-id", re: /.+/ }],
  },
  {
    slug: "prestashop", name: "PrestaShop", category: "E-commerce",
    website: "https://www.prestashop.com", icon: "🛒", confidence: 90,
    html: [{ re: /PrestaShop|id_product|add_to_cart.*prestashop/i }],
  },
  {
    slug: "magento", name: "Magento", category: "E-commerce",
    website: "https://magento.com", cpe: "cpe:2.3:a:magento:magento", icon: "🛒", confidence: 90,
    html: [{ re: /Mage\.Cookies|window\.checkout|BLANK_URL.*mage/i }],
    cookies: [{ re: /frontend_cid/i }],
  },
  {
    slug: "bigcommerce", name: "BigCommerce", category: "E-commerce",
    website: "https://www.bigcommerce.com", icon: "🛒", confidence: 100,
    html: [{ re: /bigcommerce\.com|BCApp\./i }],
  },
  {
    slug: "woocommerce", name: "WooCommerce", category: "E-commerce",
    website: "https://woocommerce.com", icon: "🛍️", confidence: 90,
    html: [{ re: /woocommerce|wc-cart|add_to_cart_button/i }],
  },

  // ── JS Frameworks ────────────────────────────────────────────────────
  {
    slug: "react", name: "React", category: "JavaScript Framework",
    website: "https://react.dev", icon: "⚛️", confidence: 90,
    html: [{ re: /react(?:\.development|\.production\.min)?\.js/i }],
    scripts: [{ re: /react(?:\.development|\.production\.min)?\.js/i }],
  },
  {
    slug: "angular", name: "Angular", category: "JavaScript Framework",
    website: "https://angular.io", icon: "🅰️", confidence: 95,
    html: [
      { re: /ng-version="([\d.]+)"/i, version: 1 },
      { re: /\bangular\.min\.js\b|angular\.js/i },
    ],
  },
  {
    slug: "vuejs", name: "Vue.js", category: "JavaScript Framework",
    website: "https://vuejs.org", icon: "💚", confidence: 90,
    html: [
      { re: /vue(?:\.runtime)?(?:\.min)?\.js/i },
      { re: /__vue_app__|data-v-[a-f0-9]+/i },
    ],
    scripts: [{ re: /vue(?:\.runtime)?(?:\.min)?\.js/i }],
  },
  {
    slug: "nextjs", name: "Next.js", category: "JavaScript Framework",
    website: "https://nextjs.org", icon: "▲", confidence: 100,
    html: [{ re: /__NEXT_DATA__|_next\/static/i }],
    headers: [{ name: "x-nextjs-cache", re: /.+/ }],
  },
  {
    slug: "nuxtjs", name: "Nuxt.js", category: "JavaScript Framework",
    website: "https://nuxt.com", icon: "💚", confidence: 100,
    html: [{ re: /__NUXT__|_nuxt\//i }],
  },
  {
    slug: "svelte", name: "Svelte", category: "JavaScript Framework",
    website: "https://svelte.dev", icon: "🔥", confidence: 85,
    html: [{ re: /svelte(?:-app|kit)?/i }],
  },
  {
    slug: "gatsby", name: "Gatsby", category: "JavaScript Framework",
    website: "https://www.gatsbyjs.com", icon: "💜", confidence: 100,
    html: [{ re: /gatsby(?:-browser|\.js)|data-gatsby/i }],
  },
  {
    slug: "remix", name: "Remix", category: "JavaScript Framework",
    website: "https://remix.run", icon: "💿", confidence: 90,
    html: [{ re: /__remix_manifest|@remix-run/i }],
  },
  {
    slug: "astro", name: "Astro", category: "JavaScript Framework",
    website: "https://astro.build", icon: "🚀", confidence: 100,
    html: [{ re: /astro-island|@astro/i }],
    headers: [{ name: "x-astro-cache-id", re: /.+/ }],
  },
  {
    slug: "emberjs", name: "Ember.js", category: "JavaScript Framework",
    website: "https://emberjs.com", icon: "🐹", confidence: 85,
    html: [{ re: /ember\.min\.js|Ember\.VERSION/i }],
  },

  // ── JS Libraries ─────────────────────────────────────────────────────
  {
    slug: "jquery", name: "jQuery", category: "JavaScript Library",
    website: "https://jquery.com", icon: "🔵", confidence: 95,
    html: [{ re: /jquery(?:\.min)?\.js(?:.*?ver(?:sion)?=([\d.]+))?/i, version: 1 }],
    scripts: [{ re: /jquery-(\d[\d.]+)(?:\.min)?\.js/i, version: 1 }],
  },
  {
    slug: "bootstrap", name: "Bootstrap", category: "UI Framework",
    website: "https://getbootstrap.com", icon: "🅱️", confidence: 90,
    html: [{ re: /bootstrap(?:\.min)?\.(?:css|js)/i }],
    scripts: [{ re: /bootstrap(?:\.bundle)?\.min\.js/i }],
  },
  {
    slug: "tailwindcss", name: "Tailwind CSS", category: "CSS Framework",
    website: "https://tailwindcss.com", icon: "💨", confidence: 85,
    html: [{ re: /tailwindcss|cdn\.tailwindcss\.com/i }],
    scripts: [{ re: /tailwindcss/i }],
  },
  {
    slug: "lodash", name: "Lodash", category: "JavaScript Library",
    website: "https://lodash.com", icon: "🔧", confidence: 85,
    scripts: [{ re: /lodash(?:\.min)?\.js/i }],
  },
  {
    slug: "moment", name: "Moment.js", category: "JavaScript Library",
    website: "https://momentjs.com", icon: "📅", confidence: 85,
    scripts: [{ re: /moment(?:\.min)?\.js/i }],
  },
  {
    slug: "fontawesome", name: "Font Awesome", category: "CSS Framework",
    website: "https://fontawesome.com", icon: "🎨", confidence: 90,
    html: [{ re: /font-awesome|fontawesome/i }],
  },
  {
    slug: "alpinejs", name: "Alpine.js", category: "JavaScript Library",
    website: "https://alpinejs.dev", icon: "🏔️", confidence: 90,
    html: [{ re: /x-data=|alpine\.js/i }],
  },
  {
    slug: "htmx", name: "htmx", category: "JavaScript Library",
    website: "https://htmx.org", icon: "⚡", confidence: 90,
    html: [{ re: /htmx\.org|hx-get=|hx-post=/i }],
  },

  // ── Analytics ────────────────────────────────────────────────────────
  {
    slug: "google-analytics", name: "Google Analytics", category: "Analytics",
    website: "https://analytics.google.com", icon: "📊", confidence: 100,
    html: [{ re: /google-analytics\.com\/(?:analytics|ga)\.js|gtag\(|GoogleAnalyticsObject|UA-\d+-\d+/i }],
  },
  {
    slug: "google-tag-manager", name: "Google Tag Manager", category: "Tag Manager",
    website: "https://tagmanager.google.com", icon: "🏷️", confidence: 100,
    html: [{ re: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/i }],
  },
  {
    slug: "hotjar", name: "Hotjar", category: "Analytics",
    website: "https://www.hotjar.com", icon: "🔥", confidence: 100,
    html: [{ re: /hotjar\.com\/c\/hotjar|hjBootstrap/i }],
  },
  {
    slug: "segment", name: "Segment", category: "Analytics",
    website: "https://segment.com", icon: "📊", confidence: 100,
    html: [{ re: /cdn\.segment\.com\/analytics\.js/i }],
  },
  {
    slug: "mixpanel", name: "Mixpanel", category: "Analytics",
    website: "https://mixpanel.com", icon: "📊", confidence: 100,
    html: [{ re: /cdn\.mxpnl\.com|mixpanel\.init/i }],
  },
  {
    slug: "intercom", name: "Intercom", category: "Customer Support",
    website: "https://www.intercom.com", icon: "💬", confidence: 100,
    html: [{ re: /widget\.intercom\.io|window\.intercomSettings/i }],
  },
  {
    slug: "hubspot", name: "HubSpot", category: "Marketing",
    website: "https://www.hubspot.com", icon: "🟠", confidence: 100,
    html: [{ re: /js\.hs-scripts\.com|hs-analytics\.net/i }],
  },
  {
    slug: "facebook-pixel", name: "Facebook Pixel", category: "Analytics",
    website: "https://www.facebook.com/business", icon: "📘", confidence: 100,
    html: [{ re: /connect\.facebook\.net.*fbevents\.js|fbq\('init'/i }],
  },
  {
    slug: "matomo", name: "Matomo", category: "Analytics",
    website: "https://matomo.org", icon: "📊", confidence: 90,
    html: [{ re: /matomo\.js|piwik\.js|Matomo\.push/i }],
  },

  // ── CDN / Infrastructure ─────────────────────────────────────────────
  {
    slug: "cloudflare", name: "Cloudflare", category: "CDN",
    website: "https://www.cloudflare.com", icon: "☁️", confidence: 100,
    headers: [{ name: "cf-ray", re: /.+/ }],
    cookies: [{ re: /__cf_bm|_cfuvid/i }],
  },
  {
    slug: "cloudfront", name: "Amazon CloudFront", category: "CDN",
    website: "https://aws.amazon.com/cloudfront", icon: "☁️", confidence: 100,
    headers: [
      { name: "x-amz-cf-id", re: /.+/ },
      { name: "via", re: /cloudfront/i },
    ],
  },
  {
    slug: "fastly", name: "Fastly", category: "CDN",
    website: "https://www.fastly.com", icon: "⚡", confidence: 100,
    headers: [{ name: "x-fastly-request-id", re: /.+/ }],
  },
  {
    slug: "akamai", name: "Akamai", category: "CDN",
    website: "https://www.akamai.com", icon: "☁️", confidence: 100,
    headers: [{ name: "x-akamai-request-id", re: /.+/ }],
  },
  {
    slug: "varnish", name: "Varnish", category: "Caching",
    website: "https://varnish-cache.org", icon: "🗄️", confidence: 100,
    headers: [
      { name: "x-varnish", re: /.+/ },
      { name: "via", re: /varnish/i },
    ],
  },

  // ── Security ─────────────────────────────────────────────────────────
  {
    slug: "recaptcha", name: "reCAPTCHA", category: "Security",
    website: "https://www.google.com/recaptcha", icon: "🤖", confidence: 100,
    html: [{ re: /recaptcha\/api\.js|www\.recaptcha\.net|grecaptcha/i }],
  },
  {
    slug: "hcaptcha", name: "hCaptcha", category: "Security",
    website: "https://www.hcaptcha.com", icon: "🤖", confidence: 100,
    html: [{ re: /hcaptcha\.com\/1\/api\.js/i }],
  },
  {
    slug: "stripe-js", name: "Stripe.js", category: "Payment",
    website: "https://stripe.com", icon: "💳", confidence: 100,
    html: [{ re: /js\.stripe\.com\/v(\d)/i, version: 1 }],
  },
  {
    slug: "paypal", name: "PayPal", category: "Payment",
    website: "https://www.paypal.com", icon: "💳", confidence: 100,
    html: [{ re: /paypal\.com\/sdk\/js|paypalobjects\.com/i }],
  },
  {
    slug: "sentry", name: "Sentry", category: "Error Tracking",
    website: "https://sentry.io", icon: "🐛", confidence: 90,
    html: [{ re: /browser\.sentry-cdn\.com|sentry\.io\/api/i }],
  },
  {
    slug: "datadog", name: "Datadog", category: "Monitoring",
    website: "https://www.datadoghq.com", icon: "🐕", confidence: 90,
    html: [{ re: /datadoghq\.com\/browser-sdk/i }],
  },
];

interface PageData {
  headers:  Record<string, string>;
  html:     string;
  cookies:  string;
  scripts:  string[];
}

function extractScripts(html: string): string[] {
  const re = /<script[^>]+src=["']([^"'>]+)["']/gi;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return out;
}

function runDetection(page: PageData): DetectedTechnology[] {
  const results = new Map<string, DetectedTechnology>();

  for (const tech of TECHS) {
    let matched = false;
    let detectedVersion: string | undefined;
    let maxConf = 0;

    // Headers
    if (tech.headers) {
      for (const p of tech.headers) {
        const val = page.headers[p.name.toLowerCase()];
        if (!val) continue;
        const m = val.match(p.re);
        if (m) { matched = true; maxConf = Math.max(maxConf, tech.confidence); detectedVersion = detectedVersion ?? ver(m, p.version); }
      }
    }

    // HTML
    if (tech.html) {
      for (const p of tech.html) {
        const m = page.html.match(p.re);
        if (m) { matched = true; maxConf = Math.max(maxConf, tech.confidence - 5); detectedVersion = detectedVersion ?? ver(m, p.version); }
      }
    }

    // Cookies
    if (tech.cookies) {
      for (const p of tech.cookies) {
        const m = page.cookies.match(p.re);
        if (m) { matched = true; maxConf = Math.max(maxConf, tech.confidence - 5); detectedVersion = detectedVersion ?? ver(m, p.version); }
      }
    }

    // Script src attrs
    if (tech.scripts) {
      for (const p of tech.scripts) {
        for (const src of page.scripts) {
          const m = src.match(p.re);
          if (m) { matched = true; maxConf = Math.max(maxConf, tech.confidence); detectedVersion = detectedVersion ?? ver(m, p.version); break; }
        }
        if (matched) break;
      }
    }

    if (matched) {
      const existing = results.get(tech.slug);
      if (!existing || maxConf > existing.confidence) {
        results.set(tech.slug, {
          slug: tech.slug, name: tech.name, category: tech.category,
          version: detectedVersion,
          confidence: maxConf,
          website: tech.website, cpe: tech.cpe, icon: tech.icon,
        });
      }
    }
  }

  return [...results.values()].sort((a, b) => b.confidence - a.confidence);
}

export async function detectTechnologies(rawUrl: string, timeoutMs = 12000, ctx: OrchestratorContext = {}): Promise<DetectedTechnology[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let url = rawUrl;
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;

  async function tryFetch(target: string): Promise<PageData | null> {
    try {
      const res = await orchestratedFetch(target, {
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; SentinelwareBot/1.0; +https://sentinelware.io)",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
        },
      }, ctx);

      const rawHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => { rawHeaders[k.toLowerCase()] = v; });
      const html = await res.text().catch(() => "");
      const cookies = rawHeaders["set-cookie"] ?? "";
      const scripts = extractScripts(html);

      return { headers: rawHeaders, html, cookies, scripts };
    } catch {
      return null;
    }
  }

  // Run signature detection (Node.js) + whatweb binary in parallel
  async function runWhatweb(): Promise<DetectedTechnology[]> {
    if (!WHATWEB_BIN) return [];
    try {
      const host = url.replace(/^https?:\/\//, "").split("/")[0];
      const { stdout } = await execAsync(
        `${WHATWEB_BIN} --log-json=- --no-errors -q ${url} 2>/dev/null`,
        { timeout: 30000 }
      );
      const results: DetectedTechnology[] = [];
      for (const line of stdout.trim().split("\n")) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          const plugins: Record<string, any> = parsed.plugins ?? {};
          for (const [name, data] of Object.entries(plugins)) {
            if (!name || name === "IP-Address" || name === "Country" || name === "HTTPServer") continue;
            const slug    = name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
            const version = Array.isArray(data?.version) ? data.version[0] : undefined;
            results.push({
              slug, name, version,
              category: "web-technology",
              confidence: 75,
              hosts: [host],
            });
          }
        } catch {}
      }
      return results;
    } catch { return []; }
  }

  try {
    let page = await tryFetch(url);
    // Fall back to HTTP if HTTPS failed
    if (!page && url.startsWith("https://")) {
      page = await tryFetch(url.replace("https://", "http://"));
    }

    const [sigResults, whatwebResults] = await Promise.all([
      page ? Promise.resolve(runDetection(page)) : Promise.resolve([] as DetectedTechnology[]),
      runWhatweb(),
    ]);

    // Merge whatweb results — skip slugs already detected by signatures (higher confidence)
    const seenSlugs = new Set(sigResults.map(t => t.slug));
    for (const t of whatwebResults) {
      if (!seenSlugs.has(t.slug)) {
        seenSlugs.add(t.slug);
        sigResults.push(t);
      }
    }

    if (!page && sigResults.length === 0) return [];
    return sigResults;
  } finally {
    clearTimeout(timer);
  }
}

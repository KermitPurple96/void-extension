"use strict";
(function () {

  // ── Helpers ─────────────────────────────────────────────────────────────────
  function jsVal(path) {
    try { return path.split(".").reduce((o, k) => o?.[k], window); } catch { return undefined; }
  }
  function metaContent(name) {
    return document.querySelector(`meta[name="${name}"]`)?.content
      || document.querySelector(`meta[property="${name}"]`)?.content || "";
  }
  function hasCookie(re) { return re.test(document.cookie); }
  function domExists(sel) { return !!document.querySelector(sel); }

  // ── Endpoint collection ──────────────────────────────────────────────────────
  const endpoints = [];
  const epSeen   = new Set();

  // Current page without its own hash
  const pageBase = location.origin + location.pathname + location.search;

  function addEp(rawUrl, method, type) {
    let url;
    try {
      const u = new URL(rawUrl, location.href);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      // Drop pure hash-navigation: same page, different #anchor only
      if (u.hash && (u.origin + u.pathname + u.search) === pageBase) return;
      // Also strip the fragment from every URL before dedup
      // (two links to /page#foo and /page#bar are the same endpoint)
      u.hash = "";
      url = u.href;
    } catch { return; }
    if (epSeen.has(url)) return;
    epSeen.add(url);
    endpoints.push({ url, method: (method || "GET").toUpperCase(), type });
  }

  document.querySelectorAll("a[href]").forEach(a => addEp(a.href, "GET", "link"));
  document.querySelectorAll("form").forEach(f =>
    addEp(f.action || location.href, (f.method || "GET").toUpperCase(), "form")
  );
  document.querySelectorAll("script[src]").forEach(s => addEp(s.src, "GET", "script"));
  performance.getEntriesByType("resource").forEach(r => {
    if (["xmlhttprequest","fetch"].includes(r.initiatorType)) addEp(r.name, "?", "api");
    if (r.initiatorType === "script") addEp(r.name, "GET", "script");
  });

  // Merge early.js captures
  const ALLOWED_METHODS = Object.freeze(new Set(["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","WS","?"]));
  const ALLOWED_TYPES   = Object.freeze(new Set(["api","link","form","script","websocket"]));
  const bhp = window.__bhp;
  if (bhp && Array.isArray(bhp.endpoints)) {
    for (const e of bhp.endpoints) {
      if (!e || typeof e !== "object" || Array.isArray(e)) continue;
      const url    = typeof e.url    === "string" ? e.url    : null;
      const method = typeof e.method === "string" && ALLOWED_METHODS.has(e.method.toUpperCase()) ? e.method : "GET";
      const type   = typeof e.type   === "string" && ALLOWED_TYPES.has(e.type)                  ? e.type   : "api";
      if (url) addEp(url, method, type);
    }
  }

  // Patch future fetch / XHR
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    const url = typeof input === "string" ? input : (input?.url ?? String(input));
    addEp(url, init?.method || "GET", "api");
    return origFetch.apply(this, arguments);
  };
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    addEp(String(url), String(method), "api");
    return origOpen.apply(this, arguments);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // TECHNOLOGY FINGERPRINTING ENGINE  (Wappalyzer-style)
  // Sources checked in order:
  //   1. Script src URLs  (catches jQuery, jQuery UI/Migrate, core-js, plugins, version via ?ver=)
  //   2. CSS link URLs    (catches Font Awesome, Bootstrap, WP plugin CSS, etc.)
  //   3. Inline scripts   (catches analytics init, framework config objects)
  //   4. Meta tags + DOM  (RSS, PWA, Open Graph, generator, fetchpriority, etc.)
  //   5. Window globals   (frameworks that expose themselves on window)
  //   6. Inferences       (WordPress → MySQL, WooCommerce → WordPress)
  //   7. API endpoints
  // ═══════════════════════════════════════════════════════════════════════════

  const technologies = [];
  const techSeen     = new Set();

  function add(name, cat, version, evidence) {
    if (techSeen.has(name)) return;
    techSeen.add(name);
    technologies.push({ name, cat, version: version || null, evidence: evidence || null });
  }

  // ── Version helpers ──────────────────────────────────────────────────────────
  function v(...paths) {
    for (const p of paths) {
      try { const val = jsVal(p); if (val && typeof val === "string") return val; } catch {}
    }
    return null;
  }
  // Extract version from ?ver=X, @X, /libX, -X.Y.Z patterns in URLs
  function verParam(url) {
    return url.match(/[?&]ver=([\d][^&"'\s]*)/)?.[1]
        || url.match(/[@/](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)(?:[/?#]|$)/)?.[1]
        || null;
  }

  // ── Collect all page resources once ─────────────────────────────────────────
  const scriptSrcs    = [...document.querySelectorAll("script[src]")].map(s => s.src);
  const linkHrefs     = [...document.querySelectorAll("link[href]")].map(l => l.href);
  const inlineScripts = [...document.querySelectorAll("script:not([src])")].map(s => s.textContent || "");
  const allRes        = [...scriptSrcs, ...linkHrefs];
  const inlineJoined  = inlineScripts.join("\n");

  // ═══════════════════════ 1. SCRIPT URL PATTERN ENGINE ════════════════════════
  const SCRIPT_RULES = [
    // ── jQuery ecosystem ─────────────────────────────────────────────────────
    { test: s => /\/jquery(?:\.min|-\d)?\.js/i.test(s) || /jquery\/jquery(?:\.min)?\.js/i.test(s),
      name: "jQuery", cat: "JavaScript Library",
      ver:  s => verParam(s) || v("jQuery.fn.jquery","$.fn.jquery") },
    { test: s => /jquery[-.]ui(?:[-.]min)?\.js/i.test(s) || /jquery\/ui\//i.test(s),
      name: "jQuery UI", cat: "UI Library",
      ver:  s => verParam(s) || v("jQuery.ui.version") },
    { test: s => /jquery[-.]migrate(?:[-.]min)?\.js/i.test(s),
      name: "jQuery Migrate", cat: "JavaScript Library",
      ver:  s => verParam(s) },
    { test: s => /jquery[-.]form(?:[-.]min)?\.js/i.test(s),
      name: "jQuery Form", cat: "JavaScript Library", ver: s => verParam(s) },
    { test: s => /jquery[-.]validate(?:[-.]min)?\.js/i.test(s),
      name: "jQuery Validation", cat: "JavaScript Library", ver: s => verParam(s) },
    { test: s => /jquery[-.]cookie(?:[-.]min)?\.js/i.test(s),
      name: "jQuery Cookie", cat: "JavaScript Library", ver: s => verParam(s) },

    // ── core-js ──────────────────────────────────────────────────────────────
    { test: s => /\bcore[-.]js\b/i.test(s),
      name: "core-js", cat: "JavaScript Library",
      ver:  s => s.match(/core[-.]js[@/-](\d[\d.]+)/i)?.[1] || verParam(s) },

    // ── Zone.js (Angular dependency) ─────────────────────────────────────────
    { test: s => /[/]zone(?:\.min)?\.js/i.test(s) && !/timezone|phonezone/i.test(s),
      name: "Zone.js", cat: "JavaScript Library",
      ver:  s => s.match(/zone[@/-](\d[\d.]+)/i)?.[1] || verParam(s) },

    // ── Emotion (CSS-in-JS) ───────────────────────────────────────────────────
    { test: s => /@emotion\/|emotion-css|emotion-server/i.test(s),
      name: "Emotion", cat: "CSS-in-JS", ver: () => null },

    // ── DatoCMS ──────────────────────────────────────────────────────────────
    { test: s => /datocms|dato-cms/i.test(s),
      name: "DatoCMS", cat: "Headless CMS", ver: () => null },

    // ── Contentful ───────────────────────────────────────────────────────────
    { test: s => /contentful/i.test(s),
      name: "Contentful", cat: "Headless CMS", ver: () => null },

    // ── Brightcove ───────────────────────────────────────────────────────────
    { test: s => /brightcove\.net|players\.brightcove|bcls\.io/i.test(s),
      name: "Brightcove", cat: "Video Player", ver: () => null },

    // ── Vimeo / Wistia ───────────────────────────────────────────────────────
    { test: s => /player\.vimeo\.com/i.test(s),
      name: "Vimeo", cat: "Video Player", ver: () => null },
    { test: s => /wistia\.com/i.test(s),
      name: "Wistia", cat: "Video Player", ver: () => null },

    // ── styled-components / Styled System ────────────────────────────────────
    { test: s => /styled-components|styletron/i.test(s),
      name: "styled-components", cat: "CSS-in-JS", ver: () => null },

    // ── Parse.ly ─────────────────────────────────────────────────────────────
    { test: s => /parsely|parse\.ly/i.test(s),
      name: "Parse.ly", cat: "Analytics", ver: () => null },

    // ── Lodash / Underscore / Moment / Day.js / Axios / date-fns ─────────────
    { test: s => /lodash(?:\.min)?\.js/i.test(s),
      name: "Lodash", cat: "JavaScript Library",
      ver:  s => s.match(/lodash[@/-](\d[\d.]+)/i)?.[1] || v("_.VERSION") },
    { test: s => /underscore(?:\.min)?\.js/i.test(s),
      name: "Underscore.js", cat: "JavaScript Library",
      ver:  s => s.match(/underscore[@/-](\d[\d.]+)/i)?.[1] },
    { test: s => /\bmoment(?:\.min)?\.js/i.test(s),
      name: "Moment.js", cat: "JavaScript Library",
      ver:  s => s.match(/moment[@/-](\d[\d.]+)/i)?.[1] || v("moment.version") },
    { test: s => /dayjs(?:\.min)?\.js/i.test(s),
      name: "Day.js", cat: "JavaScript Library",
      ver:  s => s.match(/dayjs[@/-](\d[\d.]+)/i)?.[1] || v("dayjs.version") },
    { test: s => /\baxios(?:\.min)?\.js/i.test(s),
      name: "Axios", cat: "JavaScript Library",
      ver:  s => s.match(/axios[@/-](\d[\d.]+)/i)?.[1] || v("axios.VERSION") },
    { test: s => /date[-.]fns/i.test(s),
      name: "date-fns", cat: "JavaScript Library", ver: () => null },

    // ── Modernizr ────────────────────────────────────────────────────────────
    { test: s => /modernizr/i.test(s),
      name: "Modernizr", cat: "JavaScript Library",
      ver:  s => s.match(/modernizr[.-](\d[\d.]+)/i)?.[1] },

    // ── GSAP / animation ─────────────────────────────────────────────────────
    { test: s => /gsap|greensock|TweenMax|TweenLite/i.test(s),
      name: "GSAP", cat: "JavaScript Library",
      ver:  s => s.match(/gsap[@/-](\d[\d.]+)/i)?.[1] || v("gsap.version") },

    // ── Swiper / Slick / Isotope / Masonry / AOS / Fancybox ──────────────────
    { test: s => /\bswiper(?:\.min)?\.js/i.test(s),
      name: "Swiper", cat: "JavaScript Library",
      ver:  s => s.match(/swiper[@/-](\d[\d.]+)/i)?.[1] || v("Swiper.version") },
    { test: s => /\bslick(?:\.min)?\.js/i.test(s) && !/slickdeals/i.test(s),
      name: "Slick", cat: "JavaScript Library", ver: s => verParam(s) },
    { test: s => /\bisotope(?:\.min)?\.js/i.test(s),
      name: "Isotope", cat: "JavaScript Library",
      ver:  s => s.match(/isotope[@/-](\d[\d.]+)/i)?.[1] },
    { test: s => /\bmasonry(?:\.min)?\.js/i.test(s),
      name: "Masonry", cat: "JavaScript Library",
      ver:  s => s.match(/masonry[@/-](\d[\d.]+)/i)?.[1] || v("Masonry.version") },
    { test: s => /[/.]aos(?:\.min)?\.js/i.test(s),
      name: "AOS", cat: "JavaScript Library", ver: s => verParam(s) },
    { test: s => /fancybox/i.test(s),
      name: "Fancybox", cat: "JavaScript Library",
      ver:  s => s.match(/fancybox[@/-](\d[\d.]+)/i)?.[1] },
    { test: s => /lightbox/i.test(s) && !/cloudflare/i.test(s),
      name: "Lightbox", cat: "JavaScript Library", ver: s => verParam(s) },

    // ── Media players ────────────────────────────────────────────────────────
    { test: s => /video[-.]?js(?:\.min)?\.js/i.test(s),
      name: "Video.js", cat: "Media Player",
      ver:  s => s.match(/video[-.]?js[@/-](\d[\d.]+)/i)?.[1] || v("videojs.VERSION") },
    { test: s => /jwplayer/i.test(s),
      name: "JW Player", cat: "Media Player", ver: () => v("jwplayer.version") },
    { test: s => /\bplyr(?:\.min)?\.js/i.test(s),
      name: "Plyr", cat: "Media Player",
      ver:  s => s.match(/plyr[@/-](\d[\d.]+)/i)?.[1] },

    // ── Data viz / 3D ────────────────────────────────────────────────────────
    { test: s => /chart(?:\.min|\.umd)?\.js/i.test(s) && !/flowchart/i.test(s),
      name: "Chart.js", cat: "Data Viz",
      ver:  s => s.match(/chart[@/-](\d[\d.]+)/i)?.[1] || v("Chart.version","Chart.defaults.version") },
    { test: s => /\/d3(?:\.min)?\.js|d3[@/-]\d/i.test(s),
      name: "D3.js", cat: "Data Viz",
      ver:  s => s.match(/d3[@/-](\d[\d.]+)/i)?.[1] || v("d3.version") },
    { test: s => /highcharts/i.test(s),
      name: "Highcharts", cat: "Data Viz",
      ver:  s => s.match(/highcharts[@/-](\d[\d.]+)/i)?.[1] || v("Highcharts.version") },
    { test: s => /three(?:\.min)?\.js|three[@/-]\d/i.test(s),
      name: "Three.js", cat: "3D/WebGL",
      ver:  s => s.match(/three[@/-](\d[\d.]+)/i)?.[1] || v("THREE.REVISION") },

    // ── Realtime ─────────────────────────────────────────────────────────────
    { test: s => /socket\.io(?:\.min)?\.js/i.test(s),
      name: "Socket.io", cat: "Realtime",
      ver:  s => s.match(/socket\.io[@/-](\d[\d.]+)/i)?.[1] },
    { test: s => /pusher(?:\.min)?\.js/i.test(s),
      name: "Pusher", cat: "Realtime",
      ver:  s => s.match(/pusher[@/-](\d[\d.]+)/i)?.[1] },

    // ── Rich text editors ─────────────────────────────────────────────────────
    { test: s => /tinymce/i.test(s),
      name: "TinyMCE", cat: "Rich Text Editor", ver: s => verParam(s) },
    { test: s => /ckeditor/i.test(s),
      name: "CKEditor", cat: "Rich Text Editor",
      ver:  s => s.match(/ckeditor[@/-](\d[\d.]+)/i)?.[1] || v("CKEDITOR.version") },
    { test: s => /quill(?:\.min)?\.js/i.test(s),
      name: "Quill", cat: "Rich Text Editor",
      ver:  s => s.match(/quill[@/-](\d[\d.]+)/i)?.[1] },

    // ── Icon libraries ───────────────────────────────────────────────────────
    { test: s => /font[-.]?awesome|fontawesome/i.test(s),
      name: "Font Awesome", cat: "Icon Library",
      ver:  s => s.match(/fontawesome[@/-](\d[\d.]+)/i)?.[1] || verParam(s) },

    // ── Maps ─────────────────────────────────────────────────────────────────
    { test: s => /maps\.googleapis\.com/i.test(s),
      name: "Google Maps", cat: "Maps", ver: () => null },
    { test: s => /mapbox/i.test(s),
      name: "Mapbox", cat: "Maps",
      ver:  s => s.match(/mapbox[@/-](\d[\d.]+)/i)?.[1] || v("mapboxgl.version") },
    { test: s => /leaflet(?:\.min)?\.js/i.test(s),
      name: "Leaflet", cat: "Maps",
      ver:  s => s.match(/leaflet[@/-](\d[\d.]+)/i)?.[1] || v("L.version") },

    // ── WordPress Plugins: Form Builders ─────────────────────────────────────
    { test: s => /gravityforms|gravity[-_.]form/i.test(s),
      name: "Gravity Forms", cat: "Form Builder", ver: s => verParam(s) },
    { test: s => /contact-form-7|wpcf7/i.test(s),
      name: "Contact Form 7", cat: "Form Builder", ver: s => verParam(s) },
    { test: s => /wpforms/i.test(s),
      name: "WPForms", cat: "Form Builder", ver: s => verParam(s) },
    { test: s => /fluentform|fluent-form/i.test(s),
      name: "Fluent Forms", cat: "Form Builder", ver: s => verParam(s) },

    // ── WordPress Plugins: Page Builders ─────────────────────────────────────
    { test: s => /\/plugins\/elementor\//i.test(s),
      name: "Elementor", cat: "Website Builder", ver: s => verParam(s) },
    { test: s => /\/plugins\/(?:divi|extra)\/|et[-_]builder|et[-_]core/i.test(s),
      name: "Divi", cat: "Website Builder", ver: s => verParam(s) },
    { test: s => /js[-_]composer|wpbakery|vc[-_]frontend/i.test(s),
      name: "WPBakery", cat: "Website Builder", ver: s => verParam(s) },
    { test: s => /\/plugins\/beaver-builder\/|fl[-_]builder/i.test(s),
      name: "Beaver Builder", cat: "Website Builder", ver: s => verParam(s) },
    { test: s => /\/plugins\/brizy\//i.test(s),
      name: "Brizy", cat: "Website Builder", ver: s => verParam(s) },

    // ── WordPress Plugins: SEO ────────────────────────────────────────────────
    { test: s => /\/plugins\/(?:yoast-seo|wordpress-seo|wpseo)\//i.test(s),
      name: "Yoast SEO", cat: "SEO", ver: s => verParam(s) },
    { test: s => /\/plugins\/seo-by-rank-math\//i.test(s),
      name: "Rank Math SEO", cat: "SEO", ver: s => verParam(s) },
    { test: s => /\/plugins\/all-in-one-seo/i.test(s),
      name: "All in One SEO", cat: "SEO", ver: s => verParam(s) },

    // ── WordPress Plugins: Security / Cache ───────────────────────────────────
    { test: s => /\/plugins\/wordfence\//i.test(s),
      name: "Wordfence", cat: "Security", ver: s => verParam(s) },
    { test: s => /\/plugins\/litespeed-cache\//i.test(s),
      name: "LiteSpeed Cache", cat: "Cache", ver: s => verParam(s) },
    { test: s => /\/plugins\/wp-super-cache\//i.test(s),
      name: "WP Super Cache", cat: "Cache", ver: s => verParam(s) },
    { test: s => /\/plugins\/w3-total-cache\//i.test(s),
      name: "W3 Total Cache", cat: "Cache", ver: s => verParam(s) },

    // ── WordPress Plugins: E-commerce ────────────────────────────────────────
    { test: s => /\/plugins\/woocommerce\//i.test(s) || /woocommerce[^/]*\.js/i.test(s),
      name: "WooCommerce", cat: "E-commerce", ver: s => verParam(s) },
    { test: s => /\/plugins\/easy-digital-downloads\//i.test(s),
      name: "Easy Digital Downloads", cat: "E-commerce", ver: s => verParam(s) },

    // ── WordPress Plugins: Membership / LMS ──────────────────────────────────
    { test: s => /\/plugins\/memberpress\//i.test(s),
      name: "MemberPress", cat: "Membership", ver: s => verParam(s) },
    { test: s => /\/plugins\/(?:sfwd-)?learndash\//i.test(s),
      name: "LearnDash", cat: "LMS", ver: s => verParam(s) },
    { test: s => /\/plugins\/lifterlms\//i.test(s),
      name: "LifterLMS", cat: "LMS", ver: s => verParam(s) },

    // ── WordPress Plugins: Other ──────────────────────────────────────────────
    { test: s => /\/plugins\/jetpack\//i.test(s),
      name: "Jetpack", cat: "WordPress Plugin", ver: s => verParam(s) },
    { test: s => /\/plugins\/advanced-custom-fields\/|\/plugins\/acf\//i.test(s),
      name: "Advanced Custom Fields", cat: "WordPress Plugin", ver: s => verParam(s) },
    { test: s => /\/plugins\/the-events-calendar\/|tribe[-_]events/i.test(s),
      name: "The Events Calendar", cat: "WordPress Plugin", ver: s => verParam(s) },
    { test: s => /\/plugins\/bbpress\//i.test(s),
      name: "bbPress", cat: "Forum", ver: s => verParam(s) },
    { test: s => /\/plugins\/buddypress\//i.test(s),
      name: "BuddyPress", cat: "Community", ver: s => verParam(s) },
    { test: s => /\/plugins\/polylang\//i.test(s),
      name: "Polylang", cat: "WordPress Plugin", ver: s => verParam(s) },
    { test: s => /\/plugins\/(?:wpml|sitepress-multilingual)\//i.test(s),
      name: "WPML", cat: "WordPress Plugin", ver: s => verParam(s) },
    { test: s => /\/plugins\/tablepress\//i.test(s),
      name: "TablePress", cat: "WordPress Plugin", ver: s => verParam(s) },
    { test: s => /\/plugins\/wp-mail-smtp\//i.test(s),
      name: "WP Mail SMTP", cat: "Email", ver: s => verParam(s) },
    { test: s => /\/plugins\/mailchimp-for-wp\//i.test(s),
      name: "Mailchimp for WP", cat: "Email", ver: s => verParam(s) },
    { test: s => /\/plugins\/updraftplus\//i.test(s),
      name: "UpdraftPlus", cat: "WordPress Plugin", ver: s => verParam(s) },

    // ── Analytics (script src) ────────────────────────────────────────────────
    { test: s => /google-analytics\.com\/(?:ga|analytics|gtag)\.js/i.test(s) || /googletagmanager\.com\/gtag/i.test(s),
      name: "Google Analytics", cat: "Analytics", ver: () => null },
    { test: s => /googletagmanager\.com\/gtm\.js/i.test(s),
      name: "Google Tag Manager", cat: "Analytics", ver: () => null },
    { test: s => /connect\.facebook\.net/i.test(s),
      name: "Facebook Pixel", cat: "Analytics", ver: () => null },
    { test: s => /hotjar\.com/i.test(s),
      name: "Hotjar", cat: "Analytics", ver: () => null },
    { test: s => /cdn\.segment\.com/i.test(s),
      name: "Segment", cat: "Analytics", ver: () => null },
    { test: s => /amplitude\.com/i.test(s),
      name: "Amplitude", cat: "Analytics", ver: () => null },
    { test: s => /posthog\.com/i.test(s),
      name: "PostHog", cat: "Analytics", ver: () => null },
    { test: s => /clarity\.ms/i.test(s),
      name: "Microsoft Clarity", cat: "Analytics", ver: () => null },
    { test: s => /matomo|piwik/i.test(s),
      name: "Matomo", cat: "Analytics", ver: () => null },
    { test: s => /mixpanel/i.test(s),
      name: "Mixpanel", cat: "Analytics", ver: () => null },

    // ── Monitoring / Error tracking (script src) ──────────────────────────────
    { test: s => /browser\.sentry[-.]cdn|sentry\.io\/.*\.js/i.test(s),
      name: "Sentry", cat: "Monitoring", ver: () => null },
    { test: s => /datadoghq\.com.*\.js/i.test(s),
      name: "Datadog RUM", cat: "Monitoring", ver: () => null },
    { test: s => /logrocket\.io/i.test(s),
      name: "LogRocket", cat: "Monitoring", ver: () => null },
    { test: s => /bugsnag\.com/i.test(s),
      name: "Bugsnag", cat: "Monitoring", ver: () => null },
    { test: s => /fullstory\.com/i.test(s),
      name: "FullStory", cat: "Monitoring", ver: () => null },

    // ── Auth / IAM ────────────────────────────────────────────────────────────
    { test: s => /cdn\.auth0\.com|auth0\.com/i.test(s),
      name: "Auth0", cat: "Auth / IAM", ver: () => null },
    { test: s => /okta\.com|oktacdn\.com/i.test(s),
      name: "Okta", cat: "Auth / IAM", ver: () => null },
    { test: s => /clerk\.dev|clerk\.com/i.test(s),
      name: "Clerk", cat: "Auth / IAM", ver: () => null },

    // ── Payment ───────────────────────────────────────────────────────────────
    { test: s => /js\.stripe\.com/i.test(s),
      name: "Stripe", cat: "Payment", ver: () => null },
    { test: s => /paypal\.com\/sdk|paypalobjects/i.test(s),
      name: "PayPal", cat: "Payment", ver: () => null },
    { test: s => /squareup\.com|square-cdn/i.test(s),
      name: "Square", cat: "Payment", ver: () => null },
    { test: s => /paddle\.com/i.test(s),
      name: "Paddle", cat: "Payment", ver: () => null },
    { test: s => /braintreegateway\.com/i.test(s),
      name: "Braintree", cat: "Payment", ver: () => null },

    // ── Customer Support ──────────────────────────────────────────────────────
    { test: s => /intercomcdn\.com|widget\.intercom\.io/i.test(s),
      name: "Intercom", cat: "Customer Support", ver: () => null },
    { test: s => /crisp\.chat/i.test(s),
      name: "Crisp", cat: "Customer Support", ver: () => null },
    { test: s => /tawk\.to/i.test(s),
      name: "Tawk.to", cat: "Customer Support", ver: () => null },
    { test: s => /zendesk\.com/i.test(s),
      name: "Zendesk", cat: "Customer Support", ver: () => null },

    // ── Security ──────────────────────────────────────────────────────────────
    { test: s => /recaptcha/i.test(s),
      name: "Google reCAPTCHA", cat: "Security", ver: () => null },
    { test: s => /hcaptcha\.com/i.test(s),
      name: "hCaptcha", cat: "Security", ver: () => null },
    { test: s => /challenges\.cloudflare\.com/i.test(s),
      name: "Cloudflare Turnstile", cat: "Security", ver: () => null },

    // ── CDN ───────────────────────────────────────────────────────────────────
    { test: s => /cdn\.jsdelivr\.net/i.test(s),
      name: "jsDelivr", cat: "CDN", ver: () => null },
    { test: s => /cdnjs\.cloudflare\.com/i.test(s),
      name: "cdnjs", cat: "CDN", ver: () => null },
    { test: s => /unpkg\.com/i.test(s),
      name: "unpkg", cat: "CDN", ver: () => null },
    { test: s => /cloudfront\.net/i.test(s),
      name: "AWS CloudFront", cat: "CDN", ver: () => null },
    { test: s => /akamaihd\.net|akamaistream\.net/i.test(s),
      name: "Akamai", cat: "CDN", ver: () => null },
    { test: s => /fastly\.net/i.test(s),
      name: "Fastly", cat: "CDN", ver: () => null },

    // ── BaaS ──────────────────────────────────────────────────────────────────
    { test: s => /firebase/i.test(s),
      name: "Firebase", cat: "Backend-as-a-Service",
      ver:  () => v("firebase.SDK_VERSION") },
    { test: s => /supabase/i.test(s),
      name: "Supabase", cat: "Backend-as-a-Service", ver: () => null },

    // ── Font / icon services ──────────────────────────────────────────────────
    { test: s => /fonts\.googleapis\.com|fonts\.gstatic\.com/i.test(s),
      name: "Google Fonts", cat: "Font Service", ver: () => null },
    { test: s => /use\.typekit\.net|typekit\.com/i.test(s),
      name: "Adobe Fonts", cat: "Font Service", ver: () => null },
  ];

  // Run script rules
  for (const rule of SCRIPT_RULES) {
    for (const src of scriptSrcs) {
      if (rule.test(src)) {
        let evid = "script URL";
        try { evid = `script: …${new URL(src).pathname.slice(-50)}`; } catch {}
        add(rule.name, rule.cat, rule.ver(src), evid);
        break;
      }
    }
  }

  // ═══════════════════════ 2. CSS / LINK URL ENGINE ════════════════════════════
  const CSS_RULES = [
    { test: s => /font[-.]?awesome|fontawesome/i.test(s),
      name: "Font Awesome", cat: "Icon Library",
      ver:  s => s.match(/fontawesome[@/-](\d[\d.]+)/i)?.[1] || verParam(s) },
    { test: s => /bootstrap(?![-.]icons)[^/]*\.css/i.test(s),
      name: "Bootstrap", cat: "CSS Framework",
      ver:  s => s.match(/bootstrap[@/-](\d[\d.]+)/i)?.[1] },
    { test: s => /bootstrap-icons/i.test(s),
      name: "Bootstrap Icons", cat: "Icon Library", ver: () => null },
    { test: s => /bulma/i.test(s),
      name: "Bulma", cat: "CSS Framework", ver: () => null },
    { test: s => /tailwind[^/]*\.css/i.test(s),
      name: "Tailwind CSS", cat: "CSS Framework", ver: () => null },
    { test: s => /animate\.css/i.test(s),
      name: "Animate.css", cat: "CSS Framework",
      ver:  s => s.match(/animate[@/-](\d[\d.]+)/i)?.[1] },
    { test: s => /swiper[^/]*\.css/i.test(s),
      name: "Swiper", cat: "JavaScript Library", ver: s => verParam(s) },
    { test: s => /gravityforms|gravity[-_.]form/i.test(s),
      name: "Gravity Forms", cat: "Form Builder", ver: s => verParam(s) },
    { test: s => /\/plugins\/elementor\//i.test(s),
      name: "Elementor", cat: "Website Builder", ver: s => verParam(s) },
    { test: s => /\/plugins\/woocommerce\//i.test(s),
      name: "WooCommerce", cat: "E-commerce", ver: s => verParam(s) },
    { test: s => /fonts\.googleapis\.com/i.test(s),
      name: "Google Fonts", cat: "Font Service", ver: () => null },
    { test: s => /use\.typekit\.net/i.test(s),
      name: "Adobe Fonts", cat: "Font Service", ver: () => null },
    { test: s => /dashicons/i.test(s),
      name: "WordPress", cat: "CMS", ver: s => verParam(s) },
    { test: s => /leaflet[^/]*\.css/i.test(s),
      name: "Leaflet", cat: "Maps", ver: s => verParam(s) },
  ];

  for (const rule of CSS_RULES) {
    for (const href of linkHrefs) {
      if (rule.test(href)) {
        let evid = "CSS URL";
        try { evid = `CSS: …${new URL(href).pathname.slice(-50)}`; } catch {}
        add(rule.name, rule.cat, rule.ver(href), evid);
        break;
      }
    }
  }

  // ═══════════════════════ 3. INLINE SCRIPT PATTERNS ═══════════════════════════
  const INLINE_RULES = [
    { re: /__parsely_site|parsely\.com/i,       name: "Parse.ly",            cat: "Analytics" },
    { re: /fbq\s*\(|_fbq/,                      name: "Facebook Pixel",       cat: "Analytics" },
    { re: /gtag\s*\(/,                           name: "Google Analytics",     cat: "Analytics" },
    { re: /dataLayer\.push/,                     name: "Google Tag Manager",   cat: "Analytics" },
    { re: /amplitude\.getInstance|amplitude\.init/i, name: "Amplitude",        cat: "Analytics" },
    { re: /_learnq|klaviyo/i,                    name: "Klaviyo",              cat: "Email" },
    { re: /Sentry\.init/,                        name: "Sentry",               cat: "Monitoring" },
    { re: /DD_RUM\.init|datadogRum\.init/,       name: "Datadog RUM",          cat: "Monitoring" },
    { re: /intercomSettings|Intercom\s*\(/,      name: "Intercom",             cat: "Customer Support" },
    { re: /_hsq\.push|hsConversationsSettings/i, name: "HubSpot",              cat: "Analytics" },
    { re: /mixpanel\.init/,                      name: "Mixpanel",             cat: "Analytics" },
    { re: /posthog\.init/,                       name: "PostHog",              cat: "Analytics" },
    { re: /supabase\.createClient/,              name: "Supabase",             cat: "Backend-as-a-Service" },
    { re: /firebase\.initializeApp/,             name: "Firebase",             cat: "Backend-as-a-Service" },
    { re: /Stripe\s*\(/,                         name: "Stripe",               cat: "Payment" },
    { re: /yoastSeoData|wpseo_/,                 name: "Yoast SEO",            cat: "SEO" },
    { re: /\/wp-content\//,                      name: "WordPress",            cat: "CMS" },
    { re: /wp\.apiFetch|wpApiSettings/,          name: "WordPress",            cat: "CMS" },
    { re: /Shopify\.theme/,                      name: "Shopify",              cat: "E-commerce" },
    { re: /webpackJsonp|__webpack_require__/,    name: "Webpack",              cat: "Build Tool" },
    { re: /__nuxt__|nuxtApp/i,                   name: "Nuxt.js",              cat: "Meta-Framework" },
    { re: /__remix_manifest/,                    name: "Remix",                cat: "Meta-Framework" },
  ];
  for (const { re, name, cat } of INLINE_RULES) {
    if (re.test(inlineJoined)) add(name, cat, null, "inline script");
  }

  // ═══════════════════════ 4. META TAGS + DOM SIGNALS ═══════════════════════════

  // CMS from meta generator
  const gen = metaContent("generator");
  if (gen) {
    if (/wordpress/i.test(gen))   add("WordPress",   "CMS",      gen.match(/WordPress\s*([\d.]+)/i)?.[1]  || null, "meta generator");
    if (/drupal/i.test(gen))      add("Drupal",      "CMS",      gen.match(/Drupal\s*([\d.]+)/i)?.[1]     || null, "meta generator");
    if (/joomla/i.test(gen))      add("Joomla",      "CMS",      gen.match(/Joomla!\s*([\d.]+)/i)?.[1]    || null, "meta generator");
    if (/typo3/i.test(gen))       add("TYPO3",       "CMS",      null, "meta generator");
    if (/ghost/i.test(gen))       add("Ghost",       "CMS",      gen.match(/Ghost\s*([\d.]+)/i)?.[1]      || null, "meta generator");
    if (/wix/i.test(gen))         add("Wix",         "Website Builder", null, "meta generator");
    if (/shopify/i.test(gen))     add("Shopify",     "E-commerce", null, "meta generator");
    if (/webflow/i.test(gen))     add("Webflow",     "Website Builder", null, "meta generator");
    if (/squarespace/i.test(gen)) add("Squarespace", "Website Builder", null, "meta generator");
    if (/php/i.test(gen))         add("PHP",         "Programming Language", gen.match(/PHP\/([\d.]+)/i)?.[1] || null, "meta generator");
  }

  // Emotion via DOM (style[data-emotion] is Emotion's runtime signature)
  if (document.querySelector("style[data-emotion], style[data-styled]"))
    add("Emotion", "CSS-in-JS", null, "data-emotion style tag");

  // Brightcove video player DOM
  if (domExists("video-js[data-account], [data-video-id][data-account]"))
    add("Brightcove", "Video Player", null, "Brightcove video element");

  // Font Awesome via icon classes (fas/far/fab/fa-)
  if (document.querySelector(".fa,.fas,.far,.fal,.fad,.fab,.fa-solid,.fa-regular,.fa-light,.fa-brands"))
    add("Font Awesome", "Icon Library", null, "fa/fas/fab icon classes");

  // Page feature signals
  if (document.querySelector('link[type="application/rss+xml"], link[type="application/atom+xml"]'))
    add("RSS", "Miscellaneous", null, "RSS/Atom feed link");
  if (document.querySelector('link[rel="manifest"]'))
    add("PWA", "Miscellaneous", null, "web app manifest");
  if (document.querySelector('meta[property^="og:"]'))
    add("Open Graph", "Miscellaneous", null, "og: meta tags");
  if (document.querySelector('meta[name^="twitter:"]'))
    add("Twitter Cards", "Miscellaneous", null, "twitter: meta tags");
  if (document.querySelector('script[type="application/ld+json"]'))
    add("JSON-LD / Schema.org", "Miscellaneous", null, "structured data");
  if (document.querySelector('[fetchpriority]'))
    add("Priority Hints", "Performance", null, "fetchpriority attribute");
  if (document.documentElement.hasAttribute("amp") || document.documentElement.hasAttribute("⚡"))
    add("AMP", "Miscellaneous", null, "AMP HTML");

  // ═══════════════════════ 5. WINDOW GLOBALS ═══════════════════════════════════

  // Frontend frameworks
  if (jsVal("React") || jsVal("__REACT_DEVTOOLS_GLOBAL_HOOK__"))
    add("React", "Frontend Framework", v("React.version"), "window.React");
  if (jsVal("Vue") || jsVal("__VUE__") || jsVal("__vue_devtools_global_hook__"))
    add("Vue.js", "Frontend Framework", v("Vue.version","__VUE_VERSION__"), "window.Vue");
  if (jsVal("ng") || domExists("[ng-version]"))
    add("Angular", "Frontend Framework",
      document.querySelector("[ng-version]")?.getAttribute("ng-version") || null, "ng-version");
  if (jsVal("angular") && jsVal("angular.version"))
    add("AngularJS (v1)", "Frontend Framework", v("angular.version.full"), "window.angular");
  if (domExists("[class^='svelte-'], [class*=' svelte-']"))
    add("Svelte", "Frontend Framework", null, "svelte- class");
  if (jsVal("Backbone"))   add("Backbone.js", "Frontend Framework", v("Backbone.VERSION"), "window.Backbone");
  if (jsVal("Ember") || jsVal("EmberENV")) add("Ember.js", "Frontend Framework", v("Ember.VERSION"), "window.Ember");
  if (jsVal("Alpine") || domExists("[x-data]"))
    add("Alpine.js", "Frontend Framework", v("Alpine.version"), "window.Alpine/x-data");

  // Meta-frameworks
  if (jsVal("__NEXT_DATA__") || domExists("#__NEXT_DATA__"))
    add("Next.js", "Meta-Framework", null, "__NEXT_DATA__");
  if (jsVal("__NUXT__"))  add("Nuxt.js",   "Meta-Framework", null, "__NUXT__");
  if (jsVal("__sveltekit_page") || scriptSrcs.some(s => /\/_app\/immutable\//i.test(s)))
    add("SvelteKit", "Meta-Framework", null, "SvelteKit chunk");
  if (jsVal("Astro"))     add("Astro",     "Meta-Framework", null, "window.Astro");
  if (jsVal("Gatsby") || linkHrefs.some(h => /gatsby/i.test(h)))
    add("Gatsby",    "Meta-Framework", null, "Gatsby");

  // CMS globals + path checks
  if (jsVal("wp") || allRes.some(s => /\/wp-content\/|\/wp-includes\//i.test(s)) || hasCookie(/wordpress_/i))
    add("WordPress", "CMS", null, "wp global / wp-content path");
  if (jsVal("Drupal"))   add("Drupal",   "CMS", v("Drupal.version"),    "window.Drupal");
  if (jsVal("Shopify"))  add("Shopify",  "E-commerce", v("Shopify.version"), "window.Shopify");
  if (jsVal("Mage") || domExists("[data-mage-init]"))
    add("Magento", "E-commerce", null, "Mage / data-mage-init");
  if (jsVal("PrestaShop"))
    add("PrestaShop", "E-commerce", v("prestashop.version"), "window.PrestaShop");
  if (jsVal("BCData"))   add("BigCommerce", "E-commerce", null, "BCData");
  if (jsVal("webflow") || domExists("html[data-wf-page]"))
    add("Webflow",  "Website Builder", null, "data-wf-page");
  if (jsVal("wixBiSession")) add("Wix",  "Website Builder", null, "wixBiSession");
  if (jsVal("Squarespace"))  add("Squarespace", "Website Builder", null, "window.Squarespace");
  if (jsVal("Sanity"))       add("Sanity", "Headless CMS", null, "window.Sanity");

  // Language signals
  if (hasCookie(/PHPSESSID/i) || /\.php(\?|$)/i.test(location.href) ||
      [...document.querySelectorAll("a[href]")].some(a => /\.php(\?|$)/i.test(a.href)))
    add("PHP", "Programming Language", null, "PHPSESSID / .php URL");
  if (hasCookie(/ASP\.NET_SessionId|\.ASPXAUTH/i))
    add("ASP.NET", "Programming Language", null, "ASP.NET cookie");
  if (hasCookie(/JSESSIONID/i))
    add("Java", "Programming Language", null, "JSESSIONID cookie");
  if (hasCookie(/laravel_session|XSRF-TOKEN/i))
    add("Laravel", "Framework", null, "laravel_session / XSRF-TOKEN");
  // Django: require the specific csrfmiddlewaretoken input (very Django-specific)
  if (domExists("input[name='csrfmiddlewaretoken']"))
    add("Django", "Framework", null, "csrfmiddlewaretoken input");
  if (domExists("[data-phx-view], [data-phx-main]"))
    add("Phoenix (Elixir)", "Framework", null, "phx-view attr");
  if (jsVal("__RUBY_ON_RAILS__") || scriptSrcs.some(s => /rails-ujs/i.test(s)))
    add("Ruby on Rails", "Framework", null, "rails-ujs");

  // CSS / UI frameworks
  const hasTwVars = (() => {
    try {
      for (const s of document.querySelectorAll("style")) {
        if (s.textContent.includes("--tw-")) return true;
      }
      for (const sheet of document.styleSheets) {
        try {
          for (const rule of sheet.cssRules || []) {
            if (rule.cssText && rule.cssText.includes("--tw-")) return true;
          }
        } catch {}
      }
    } catch {}
    return false;
  })();
  if (hasTwVars) add("Tailwind CSS", "CSS Framework", null, "--tw- CSS variables");
  if (jsVal("bootstrap") || linkHrefs.some(h => /bootstrap/i.test(h)))
    add("Bootstrap", "CSS Framework", v("bootstrap.Tooltip.VERSION"), "window.bootstrap");
  if (jsVal("UIkit")) add("UIkit", "CSS Framework", v("UIkit.version"), "window.UIkit");
  // Ant Design: require specific component class names to avoid false positives
  if (jsVal("antd") ||
      domExists("[class*='ant-btn']") || domExists("[class*='ant-modal']") ||
      domExists("[class*='ant-table']") || domExists("[class*='ant-menu']") ||
      domExists("[class*='ant-form-item']"))
    add("Ant Design", "UI Library", null, "ant-component classes");
  if (domExists("[class*='MuiBox-'], [class*='MuiButton-']"))
    add("Material-UI (MUI)", "UI Library", null, "Mui class");
  if (domExists("[class*='chakra-']"))
    add("Chakra UI", "UI Library", null, "chakra- class");
  if (domExists("[data-radix-popper-content-wrapper],[data-radix-scroll-area-viewport]," +
                "[data-radix-collection-item],[data-radix-focus-guard]") ||
      document.querySelector("[class*='radix']") !== null)
    add("Radix UI", "UI Library", null, "radix data-attributes");

  // shadcn/ui — unique CSS variable combination
  const hasShadcnCSS = (() => {
    try {
      for (const s of document.querySelectorAll("style")) {
        const t = s.textContent;
        if (t.includes("--muted-foreground") && t.includes("--destructive-foreground")) return true;
        if (t.includes("--accent-foreground") && t.includes("--card-foreground")) return true;
      }
      const cs = getComputedStyle(document.documentElement);
      const hits = ["--muted-foreground","--destructive-foreground","--accent-foreground","--ring","--card-foreground"]
        .filter(p => cs.getPropertyValue(p).trim().length > 0);
      return hits.length >= 3;
    } catch {}
    return false;
  })();
  if (hasShadcnCSS) {
    add("shadcn/ui",    "UI Library",    null, "shadcn CSS variables");
    add("Tailwind CSS", "CSS Framework", null, "shadcn/ui dependency");
    add("Radix UI",     "UI Library",    null, "shadcn/ui dependency");
  }

  // Build tools
  if (jsVal("__webpack_require__") || jsVal("webpackJsonp"))
    add("Webpack", "Build Tool", null, "__webpack_require__");
  if (scriptSrcs.some(s => /\/@vite\/|\/vite\//i.test(s)) || domExists("script[src*='/@vite/client']"))
    add("Vite", "Build Tool", null, "@vite/client");
  if (jsVal("parcelRequire")) add("Parcel", "Build Tool", null, "parcelRequire");
  if (jsVal("__turbopack__")) add("Turbopack", "Build Tool", null, "__turbopack__");

  // Global fallbacks for libs that expose window.X (if not already caught by URL rules)
  if (jsVal("jQuery")     && !techSeen.has("jQuery"))
    add("jQuery",    "JavaScript Library", v("jQuery.fn.jquery","$.fn.jquery"), "window.jQuery");
  if (jsVal("Chart")      && !techSeen.has("Chart.js"))
    add("Chart.js",  "Data Viz", v("Chart.version","Chart.defaults.version"), "window.Chart");
  if (jsVal("d3")         && !techSeen.has("D3.js"))
    add("D3.js",     "Data Viz", v("d3.version"), "window.d3");
  if (jsVal("Highcharts") && !techSeen.has("Highcharts"))
    add("Highcharts","Data Viz", v("Highcharts.version"), "window.Highcharts");
  if (jsVal("THREE")      && !techSeen.has("Three.js"))
    add("Three.js",  "3D/WebGL", v("THREE.REVISION"), "window.THREE");
  if (jsVal("L") && jsVal("L.version") && !techSeen.has("Leaflet"))
    add("Leaflet",   "Maps", v("L.version"), "window.L");
  if (jsVal("io") && jsVal("io.Socket") && !techSeen.has("Socket.io"))
    add("Socket.io", "Realtime", null, "window.io.Socket");
  if (jsVal("tinyMCE")   && !techSeen.has("TinyMCE"))
    add("TinyMCE",   "Rich Text Editor", null, "window.tinyMCE");
  if (jsVal("CKEDITOR")  && !techSeen.has("CKEditor"))
    add("CKEditor",  "Rich Text Editor", v("CKEDITOR.version"), "window.CKEDITOR");
  if (jsVal("Pusher")    && !techSeen.has("Pusher"))
    add("Pusher",    "Realtime", null, "window.Pusher");
  if (jsVal("mapboxgl")  && !techSeen.has("Mapbox"))
    add("Mapbox",    "Maps", v("mapboxgl.version"), "window.mapboxgl");
  if (jsVal("google") && jsVal("google.maps") && !techSeen.has("Google Maps"))
    add("Google Maps","Maps", null, "google.maps");
  if (jsVal("firebase")  && !techSeen.has("Firebase"))
    add("Firebase",  "Backend-as-a-Service", v("firebase.SDK_VERSION"), "window.firebase");
  if (jsVal("supabase")  && !techSeen.has("Supabase"))
    add("Supabase",  "Backend-as-a-Service", null, "window.supabase");
  if (jsVal("gtag") || jsVal("ga") || jsVal("_gaq"))
    add("Google Analytics", "Analytics", null, "window.gtag/ga");
  if (jsVal("dataLayer"))
    add("Google Tag Manager", "Analytics", null, "window.dataLayer");
  if (jsVal("fbq"))   add("Facebook Pixel", "Analytics", null, "window.fbq");
  if (jsVal("hj") || jsVal("_hjSettings"))
    add("Hotjar", "Analytics", null, "window.hj");
  if (jsVal("mixpanel")) add("Mixpanel", "Analytics", null, "window.mixpanel");
  if (jsVal("Sentry") || jsVal("__SENTRY__"))
    add("Sentry", "Monitoring", null, "window.Sentry");
  if (jsVal("newrelic") || jsVal("NREUM"))
    add("New Relic", "Monitoring", null, "window.newrelic");
  if (jsVal("DD_RUM"))  add("Datadog RUM", "Monitoring", null, "window.DD_RUM");
  if (jsVal("Intercom")) add("Intercom", "Customer Support", null, "window.Intercom");
  if (jsVal("Clerk"))   add("Clerk", "Auth / IAM", null, "window.Clerk");
  if (jsVal("__NEXT_AUTH") || scriptSrcs.some(s => /next-auth/i.test(s)))
    add("NextAuth.js", "Auth / IAM", null, "__NEXT_AUTH");
  if (jsVal("Stripe"))  add("Stripe", "Payment", null, "window.Stripe");
  if (hasCookie(/__cf_bm|__cfduid|cf_clearance/i) && !techSeen.has("Cloudflare"))
    add("Cloudflare", "CDN / Security", null, "CF cookies");
  if (jsVal("grecaptcha") && !techSeen.has("Google reCAPTCHA"))
    add("Google reCAPTCHA", "Security", null, "window.grecaptcha");
  if (jsVal("hcaptcha") && !techSeen.has("hCaptcha"))
    add("hCaptcha", "Security", null, "window.hcaptcha");
  if (jsVal("turnstile") && !techSeen.has("Cloudflare Turnstile"))
    add("Cloudflare Turnstile", "Security", null, "window.turnstile");

  // ═══════════════════════ 6. INFERRED TECHNOLOGIES ════════════════════════════
  // WordPress → MySQL
  if (techSeen.has("WordPress") && !techSeen.has("MySQL"))
    add("MySQL", "Database", null, "WordPress (inferred)");
  // WooCommerce → WordPress
  if (techSeen.has("WooCommerce") && !techSeen.has("WordPress"))
    add("WordPress", "CMS", null, "WooCommerce dependency");
  // Angular / NestJS → TypeScript (these frameworks require TypeScript)
  if ((techSeen.has("Angular") || techSeen.has("NestJS")) && !techSeen.has("TypeScript"))
    add("TypeScript", "Programming Language", null, "Angular (inferred)");
  // Zone.js → Angular (if Zone.js found without Angular already detected)
  if (techSeen.has("Zone.js") && !techSeen.has("Angular"))
    add("Angular", "Frontend Framework", null, "Zone.js (inferred)");
  // Emotion → React (Emotion is a React CSS-in-JS lib)
  if (techSeen.has("Emotion") && !techSeen.has("React"))
    add("React", "Frontend Framework", null, "Emotion (inferred)");
  // Catch CloudFront in CSS/link hrefs too
  if (!techSeen.has("AWS CloudFront") && allRes.some(r => /cloudfront\.net/i.test(r)))
    add("AWS CloudFront", "CDN", null, "cloudfront.net resource");

  // ═══════════════════════ 7. API ENDPOINT PATTERNS ════════════════════════════
  if (endpoints.some(e => /\/graphql/i.test(e.url)))
    add("GraphQL", "API Protocol", null, "/graphql endpoint");
  if (endpoints.some(e => /\/api\/v[\d]+/i.test(e.url)))
    add("REST API (versioned)", "API Protocol", null, "/api/v* endpoint");
  if (endpoints.some(e => /\/trpc/i.test(e.url)))
    add("tRPC", "API Protocol", null, "/trpc endpoint");

  // ── REPORT ───────────────────────────────────────────────────────────────────
  chrome.runtime.sendMessage({ type: "REPORT", endpoints, technologies });

})();

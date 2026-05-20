function hasHeaderStartingWith(headers, prefix) {
    return Object.keys(headers).some(k => k.startsWith(prefix));
}
function headerContains(headers, key, search) {
    return (headers[key] ?? '').toLowerCase().includes(search.toLowerCase());
}
export const patterns = [
    // CMS
    { name: 'WordPress', category: 'CMS', check: (h, b) => /wp-content|wp-json|\/wp-includes|generator["\s:=]+WordPress/i.test(b) || headerContains(h, 'x-powered-by', 'WP Engine') },
    { name: 'Shopify', category: 'CMS', check: (h, b) => /shopify\.com|Shopify\.theme|Shopify\.shop|cdn\.shopify/i.test(b) || !!h['x-shopid'] || hasHeaderStartingWith(h, 'x-storefront') },
    { name: 'Wix', category: 'CMS', check: (h, b) => /wix\.com|X-Wix-/i.test(b) || hasHeaderStartingWith(h, 'x-wix') },
    { name: 'Squarespace', category: 'CMS', check: (h, b) => /squarespace\.com|Squarespace/i.test(b) || hasHeaderStartingWith(h, 'x-squarespace') },
    { name: 'Drupal', category: 'CMS', check: (h, b) => /sites\/(default|all)\/|Drupal\.settings|drupal\.js/i.test(b) },
    { name: 'Joomla', category: 'CMS', check: (h, b) => /\/media\/jui\/|Joomla!/i.test(b) },
    { name: 'Webflow', category: 'CMS', check: (h, b) => /webflow\.js|webflow\.com/i.test(b) },
    { name: 'Ghost', category: 'CMS', check: (h, b) => /ghost\.io|Ghost [\d.]+/i.test(b) || headerContains(h, 'x-powered-by', 'Ghost') },
    // JavaScript frameworks
    { name: 'Next.js', category: 'Framework', check: (h, b) => /__NEXT_DATA__|_buildManifest|_next\/static/i.test(b) || hasHeaderStartingWith(h, 'x-nextjs') || !!h['x-vercel-id'] },
    { name: 'Nuxt.js', category: 'Framework', check: (h, b) => /__NUXT__|_nuxt\/|nuxt\./i.test(b) },
    { name: 'Gatsby', category: 'Framework', check: (h, b) => /gatsby-/i.test(b) || hasHeaderStartingWith(h, 'x-gatsby') || headerContains(h, 'x-powered-by', 'Gatsby') },
    { name: 'React', category: 'Framework', check: (h, b) => /data-reactroot|data-reactid|react\.js|react\.min\.js|__REACT_/i.test(b) },
    { name: 'Vue.js', category: 'Framework', check: (h, b) => /vue\.js|vue\.min\.js|data-v-[a-f0-9]{6,}/i.test(b) },
    { name: 'Angular', category: 'Framework', check: (h, b) => /ng-version|angular\.js|angular\.min\.js/i.test(b) },
    { name: 'Svelte', category: 'Framework', check: (h, b) => /svelte\.js|svelte\.min\.js|__svelte/i.test(b) },
    { name: 'Astro', category: 'Framework', check: (h, b) => /astro\.js|astro-/i.test(b) || headerContains(h, 'x-powered-by', 'Astro') },
    { name: 'Remix', category: 'Framework', check: (h, b) => /remix\.js|__remix|@remix-run/i.test(b) },
    // CSS frameworks
    { name: 'Tailwind CSS', category: 'CSS Framework', check: (h, b) => /tailwind/i.test(b) || headerContains(h, 'x-powered-by', 'Tailwind') },
    { name: 'Bootstrap', category: 'CSS Framework', check: (h, b) => /bootstrap\.(min\.)?css|bootstrap\.(min\.)?js/i.test(b) },
    // Analytics & Marketing
    { name: 'Google Analytics', category: 'Analytics', check: (h, b) => /gtag\s*\(|ga\s*\(|google-analytics\.com|googletagmanager/i.test(b) },
    { name: 'Google Tag Manager', category: 'Analytics', check: (h, b) => /googletagmanager\.com\/gtm/i.test(b) },
    { name: 'Facebook Pixel', category: 'Analytics', check: (h, b) => /fbq\s*\(|facebook\.com\/tr\//i.test(b) },
    { name: 'Hotjar', category: 'Analytics', check: (h, b) => /hotjar/i.test(b) },
    { name: 'Mixpanel', category: 'Analytics', check: (h, b) => /mixpanel/i.test(b) },
    { name: 'HubSpot', category: 'Analytics', check: (h, b) => /js\.hs-scripts\.com|hs-analytics|HubSpot/i.test(b) },
    { name: 'Intercom', category: 'Analytics', check: (h, b) => /intercom/i.test(b) },
    { name: 'Amplitude', category: 'Analytics', check: (h, b) => /amplitude/i.test(b) },
    { name: 'Segment', category: 'Analytics', check: (h, b) => /segment\.com\/analytics|analytics\.js/i.test(b) },
    { name: 'Clarity', category: 'Analytics', check: (h, b) => /clarity\.ms|clarity/i.test(b) },
    // CDN / Hosting
    { name: 'Cloudflare', category: 'CDN', check: (h, b) => !!h['cf-ray'] || headerContains(h, 'server', 'cloudflare') || !!h['cf-cache-status'] },
    { name: 'Akamai', category: 'CDN', check: (h, b) => hasHeaderStartingWith(h, 'x-akamai') || !!h['x-akamai-transformed'] },
    { name: 'Fastly', category: 'CDN', check: (h, b) => headerContains(h, 'x-served-by', 'cache') || hasHeaderStartingWith(h, 'x-fastly') },
    { name: 'AWS CloudFront', category: 'CDN', check: (h, b) => !!h['x-amz-cf-id'] || !!h['x-amz-cf-pop'] || headerContains(h, 'server', 'CloudFront') },
    { name: 'Netlify', category: 'Hosting', check: (h, b) => headerContains(h, 'server', 'Netlify') || !!h['x-nf-request-id'] },
    { name: 'Vercel', category: 'Hosting', check: (h, b) => !!h['x-vercel-id'] || !!h['x-vercel-cache'] },
    { name: 'GitHub Pages', category: 'Hosting', check: (h, b) => headerContains(h, 'server', 'GitHub.com') },
    { name: 'Render', category: 'Hosting', check: (h, b) => headerContains(h, 'server', 'Render') },
    { name: 'Heroku', category: 'Hosting', check: (h, b) => /heroku/i.test(JSON.stringify(h)) },
    { name: 'AWS', category: 'Hosting', check: (h, b) => hasHeaderStartingWith(h, 'x-amz-') || headerContains(h, 'server', 'Amazon') || headerContains(h, 'server', 'awseb') },
    { name: 'Google Cloud', category: 'Hosting', check: (h, b) => /google\.com|gstatic\.com/i.test(b) || headerContains(h, 'via', 'google') },
    { name: 'DigitalOcean', category: 'Hosting', check: (h, b) => /digitalocean/i.test(JSON.stringify(h)) },
    { name: 'Namecheap', category: 'Hosting', check: (h, b) => /namecheap/i.test(JSON.stringify(h)) },
    // Email / ESP
    { name: 'Mailchimp', category: 'Email', check: (h, b) => /mailchimp|MC\-/i.test(b) || hasHeaderStartingWith(h, 'x-mc') },
    { name: 'SendGrid', category: 'Email', check: (h, b) => /sendgrid/i.test(b) || hasHeaderStartingWith(h, 'x-sg') },
    { name: 'Mailgun', category: 'Email', check: (h, b) => /mailgun/i.test(b) || hasHeaderStartingWith(h, 'x-mailgun') },
    { name: 'ConvertKit', category: 'Email', check: (h, b) => /convertkit/i.test(b) },
    { name: 'ActiveCampaign', category: 'Email', check: (h, b) => /activecampaign/i.test(b) },
    // Payment
    { name: 'Stripe', category: 'Payment', check: (h, b) => /stripe\.com|js\.stripe\.com|pk_(live|test)_/i.test(b) },
    { name: 'PayPal', category: 'Payment', check: (h, b) => /paypal/i.test(b) },
    { name: 'Shopify Payments', category: 'Payment', check: (h, b) => /shopifypayments/i.test(b) },
    // Live chat
    { name: 'Intercom', category: 'Live Chat', check: (h, b) => /intercom\.io|intercomcdn/i.test(b) },
    { name: 'Drift', category: 'Live Chat', check: (h, b) => /drift\.com|driftcdn/i.test(b) },
    { name: 'Crisp', category: 'Live Chat', check: (h, b) => /crisp\.chat|crisp\.im/i.test(b) },
    { name: 'Tidio', category: 'Live Chat', check: (h, b) => /tidio\.co/i.test(b) },
    { name: 'LiveChat', category: 'Live Chat', check: (h, b) => /livechat\.com|livechatinc/i.test(b) },
    { name: 'Zendesk', category: 'Live Chat', check: (h, b) => /zendesk/i.test(b) },
    { name: 'Tawk.to', category: 'Live Chat', check: (h, b) => /tawk\.to/i.test(b) },
];
export function detectTech(headers, body) {
    const detected = [];
    for (const p of patterns) {
        try {
            if (p.check(headers, body))
                detected.push({ name: p.name, category: p.category });
        }
        catch { /* skip pattern on error */ }
    }
    return detected;
}

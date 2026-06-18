import { getUncachableStripeClient } from "../../artifacts/api-server/src/lib/stripeClient";

const PLANS = [
  {
    name: "Starter",
    description: "For small teams getting started with threat exposure management.",
    priceUsd: 4900,
    metadata: { slug: "starter", maxAssets: "25", maxUsers: "5" },
  },
  {
    name: "Pro",
    description: "Full CTEM capabilities for growing security teams.",
    priceUsd: 19900,
    metadata: { slug: "pro", maxAssets: "200", maxUsers: "25" },
  },
  {
    name: "Enterprise",
    description: "Unlimited scale with dedicated support and custom integrations.",
    priceUsd: 0,
    metadata: { slug: "enterprise", maxAssets: "unlimited", maxUsers: "unlimited" },
  },
];

async function seedProducts() {
  const stripe = await getUncachableStripeClient();

  for (const plan of PLANS) {
    const existing = await stripe.products.search({ query: `name:'${plan.name}' AND active:'true'` });
    if (existing.data.length > 0) {
      console.log(`${plan.name} already exists (${existing.data[0].id}), skipping.`);
      continue;
    }

    const product = await stripe.products.create({
      name: plan.name,
      description: plan.description,
      metadata: plan.metadata,
    });
    console.log(`Created product: ${product.name} (${product.id})`);

    if (plan.priceUsd > 0) {
      const price = await stripe.prices.create({
        product: product.id,
        unit_amount: plan.priceUsd,
        currency: "usd",
        recurring: { interval: "month" },
      });
      console.log(`  Created price: $${plan.priceUsd / 100}/month (${price.id})`);
    } else {
      console.log(`  Enterprise plan — no automated price created (contact sales).`);
    }
  }

  console.log("\nDone. Webhooks will sync products to your local DB automatically.");
}

seedProducts().catch(err => { console.error(err); process.exit(1); });

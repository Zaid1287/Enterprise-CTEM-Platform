import { Router } from "express";
import { eq, sql } from "drizzle-orm";
import { db, tenantsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { getUncachableStripeClient } from "../lib/stripeClient";

const router = Router();

// ── List products with prices (public) ────────────────────────────────────────

router.get("/stripe/products", async (_req, res): Promise<void> => {
  try {
    const rows = await db.execute(sql`
      SELECT
        p.id as product_id,
        p.name as product_name,
        p.description as product_description,
        p.active as product_active,
        p.metadata as product_metadata,
        pr.id as price_id,
        pr.unit_amount,
        pr.currency,
        pr.recurring,
        pr.active as price_active
      FROM stripe.products p
      LEFT JOIN stripe.prices pr ON pr.product = p.id AND pr.active = true
      WHERE p.active = true
      ORDER BY pr.unit_amount ASC NULLS LAST
    `);

    const productsMap = new Map<string, any>();
    for (const row of rows.rows) {
      if (!productsMap.has(row.product_id as string)) {
        productsMap.set(row.product_id as string, {
          id: row.product_id,
          name: row.product_name,
          description: row.product_description,
          metadata: row.product_metadata ?? {},
          prices: [],
        });
      }
      if (row.price_id) {
        productsMap.get(row.product_id as string).prices.push({
          id: row.price_id,
          unitAmount: row.unit_amount,
          currency: row.currency,
          recurring: row.recurring,
        });
      }
    }

    res.json({ products: Array.from(productsMap.values()) });
  } catch (err: any) {
    // Stripe schema may not exist yet
    res.json({ products: [] });
  }
});

// ── Get tenant subscription ────────────────────────────────────────────────────

router.get("/stripe/subscription", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;

  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, tenantId));
  if (!tenant?.stripeSubscriptionId) {
    res.json({ subscription: null });
    return;
  }

  try {
    const rows = await db.execute(sql`
      SELECT * FROM stripe.subscriptions WHERE id = ${tenant.stripeSubscriptionId}
    `);
    res.json({ subscription: rows.rows[0] ?? null });
  } catch {
    res.json({ subscription: null });
  }
});

// ── Create checkout session ────────────────────────────────────────────────────

router.post("/stripe/checkout", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { priceId } = req.body;

  if (!priceId) {
    res.status(400).json({ error: "priceId is required" });
    return;
  }

  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, tenantId));
  const stripe = await getUncachableStripeClient();

  let customerId = tenant?.stripeCustomerId ?? undefined;
  if (!customerId) {
    const customer = await stripe.customers.create({
      email: req.user!.email,
      metadata: { tenantId: String(tenantId) },
    });
    customerId = customer.id;
    await db.update(tenantsTable)
      .set({ stripeCustomerId: customerId })
      .where(eq(tenantsTable.id, tenantId));
  }

  const domain = process.env.REPLIT_DOMAINS?.split(",")[0];
  const baseUrl = domain ? `https://${domain}` : `${req.protocol}://${req.get("host")}`;

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    payment_method_types: ["card"],
    line_items: [{ price: priceId, quantity: 1 }],
    mode: "subscription",
    success_url: `${baseUrl}/settings/account?tab=billing&checkout=success`,
    cancel_url: `${baseUrl}/settings/account?tab=billing&checkout=cancel`,
  });

  res.json({ url: session.url });
});

// ── Customer portal ────────────────────────────────────────────────────────────

router.post("/stripe/portal", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;

  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, tenantId));
  if (!tenant?.stripeCustomerId) {
    res.status(400).json({ error: "No billing account found" });
    return;
  }

  const stripe = await getUncachableStripeClient();
  const domain = process.env.REPLIT_DOMAINS?.split(",")[0];
  const baseUrl = domain ? `https://${domain}` : `${req.protocol}://${req.get("host")}`;

  const portalSession = await stripe.billingPortal.sessions.create({
    customer: tenant.stripeCustomerId,
    return_url: `${baseUrl}/settings/account?tab=billing`,
  });

  res.json({ url: portalSession.url });
});

export default router;

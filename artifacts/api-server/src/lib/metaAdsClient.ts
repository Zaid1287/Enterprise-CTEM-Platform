import { logger } from "./logger";

export interface MetaAd {
  adId: string;
  adType: string;
  title: string | null;
  body: string | null;
  advertiserName: string | null;
  advertiserPage: string | null;
  impressions: string | null;
  spend: string | null;
  currency: string | null;
  startDate: string | null;
  endDate: string | null;
  deliveryCountries: string[];
  snapshotUrl: string | null;
  risk: "low" | "medium" | "high" | "critical";
}

const META_ADS_API = "https://graph.facebook.com/v19.0/ads_archive";

function assessAdRisk(ad: Partial<MetaAd>, brandName: string): "low" | "medium" | "high" | "critical" {
  const text = `${ad.title ?? ""} ${ad.body ?? ""} ${ad.advertiserName ?? ""}`.toLowerCase();
  const brand = brandName.toLowerCase();
  if (text.includes("official") || text.includes("verify") || text.includes("login") || text.includes("account")) return "critical";
  if (text.includes(brand) && (text.includes("free") || text.includes("giveaway") || text.includes("prize"))) return "high";
  if (text.includes(brand)) return "medium";
  return "low";
}

export async function scanMetaAds(brandName: string, domain: string, accessToken: string): Promise<MetaAd[]> {
  const results: MetaAd[] = [];

  const searchTerms = [brandName, domain];
  for (const term of searchTerms) {
    try {
      const params = new URLSearchParams({
        search_terms: term,
        ad_type: "ALL",
        ad_reached_countries: "['US']",
        fields: [
          "id",
          "ad_snapshot_url",
          "page_name",
          "page_id",
          "ad_creative_bodies",
          "ad_creative_link_titles",
          "impressions",
          "spend",
          "currency",
          "ad_delivery_start_time",
          "ad_delivery_stop_time",
          "delivery_by_region",
        ].join(","),
        limit: "30",
        access_token: accessToken,
      });

      const res = await fetch(`${META_ADS_API}?${params.toString()}`, {
        signal: AbortSignal.timeout(15_000),
      });

      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        logger.warn({ status: res.status, term, errText }, "Meta Ads API non-OK response");
        continue;
      }

      const data = await res.json() as {
        data?: Array<{
          id: string;
          page_name?: string;
          page_id?: string;
          ad_creative_bodies?: string[];
          ad_creative_link_titles?: string[];
          impressions?: { lower_bound: string; upper_bound: string };
          spend?: { lower_bound: string; upper_bound: string };
          currency?: string;
          ad_delivery_start_time?: string;
          ad_delivery_stop_time?: string;
          ad_snapshot_url?: string;
        }>;
        error?: { message: string; code: number };
      };

      if (data.error) {
        logger.warn({ error: data.error, term }, "Meta Ads API error");
        continue;
      }

      for (const ad of data.data ?? []) {
        const title = ad.ad_creative_link_titles?.[0] ?? null;
        const body = ad.ad_creative_bodies?.[0] ?? null;
        const impressions = ad.impressions
          ? `${ad.impressions.lower_bound}-${ad.impressions.upper_bound}`
          : null;
        const spend = ad.spend
          ? `${ad.spend.lower_bound}-${ad.spend.upper_bound}`
          : null;

        const partial: Partial<MetaAd> = {
          adId: ad.id,
          adType: "sponsored",
          title,
          body,
          advertiserName: ad.page_name ?? null,
          advertiserPage: ad.page_id
            ? `https://www.facebook.com/${ad.page_id}`
            : null,
          impressions,
          spend,
          currency: ad.currency ?? null,
          startDate: ad.ad_delivery_start_time ?? null,
          endDate: ad.ad_delivery_stop_time ?? null,
          deliveryCountries: [],
          snapshotUrl: ad.ad_snapshot_url ?? null,
        };

        const risk = assessAdRisk(partial, brandName);
        results.push({ ...partial, risk } as MetaAd);
      }
    } catch (err) {
      logger.warn({ err, term }, "Meta Ads scan error");
    }
  }

  const seen = new Set<string>();
  return results.filter(a => {
    if (seen.has(a.adId)) return false;
    seen.add(a.adId);
    return true;
  });
}

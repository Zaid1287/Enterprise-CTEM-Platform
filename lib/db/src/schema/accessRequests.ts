import { pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

export const accessRequestsTable = pgTable("access_requests", {
  id: serial("id").primaryKey(),
  requestType: text("request_type").notNull().default("access"),
  fullName: text("full_name").notNull(),
  companyName: text("company_name").notNull(),
  email: text("email").notNull(),
  jobTitle: text("job_title"),
  teamSize: text("team_size"),
  phone: text("phone"),
  message: text("message"),
  planName: text("plan_name"),
  tenantId: text("tenant_id"),
  status: text("status").notNull().default("pending"),
  reviewedByUserId: text("reviewed_by_user_id"),
  reviewNotes: text("review_notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

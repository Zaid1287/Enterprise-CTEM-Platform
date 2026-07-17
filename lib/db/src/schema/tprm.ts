import { pgTable, serial, integer, text, boolean, jsonb, real, timestamp, date, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";

export const tprmModuleAssignmentsTable = pgTable("tprm_module_assignments", {
  tenantId:  integer("tenant_id").primaryKey().references(() => tenantsTable.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").notNull().default(false),
  enabledBy: integer("enabled_by").references(() => usersTable.id, { onDelete: "set null" }),
  enabledAt: timestamp("enabled_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
});

export const tprmVendorsTable = pgTable("tprm_vendors", {
  id:             serial("id").primaryKey(),
  tenantId:       integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  companyName:    text("company_name").notNull(),
  slug:           text("slug").notNull(),
  domain:         text("domain").notNull(),
  type:           text("type").notNull().default("service_provider"),
  industry:       text("industry"),
  description:    text("description"),
  logoUrl:        text("logo_url"),
  website:        text("website"),
  employeeCount:  integer("employee_count"),
  companySize:    text("company_size"),
  founded:        text("founded"),
  location:       text("location"),
  marketCap:      text("market_cap"),
  companyType:    text("company_type").default("private"),
  isGlobal:       boolean("is_global").notNull().default(false),
  inherentRisk:   text("inherent_risk").notNull().default("medium"),
  riskScore:      integer("risk_score").notNull().default(0),
  riskGrade:      text("risk_grade").notNull().default("F"),
  businessImpact: integer("business_impact").notNull().default(5),
  scanFrequency:  text("scan_frequency").notNull().default("weekly"),
  status:         text("status").notNull().default("pending"),
  source:         text("source").notNull().default("manual"),
  assessmentType:        text("assessment_type").notNull().default("continuous"),
  slaUptimePercent:      real("sla_uptime_percent"),
  slaResponseTimeHours:  integer("sla_response_time_hours"),
  slaReviewDate:         date("sla_review_date"),
  slaNotes:              text("sla_notes"),
  slaBreachCount:        integer("sla_breach_count").notNull().default(0),
  lastScannedAt:         timestamp("last_scanned_at", { withTimezone: true }),
  createdBy:             integer("created_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:             timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:             timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorRiskScoresTable = pgTable("tprm_vendor_risk_scores", {
  id:              serial("id").primaryKey(),
  vendorId:        integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  overallScore:    integer("overall_score").notNull().default(0),
  networkScore:    integer("network_score").notNull().default(0),
  dnsScore:        integer("dns_score").notNull().default(0),
  webAppScore:     integer("web_app_score").notNull().default(0),
  emailScore:      integer("email_score").notNull().default(0),
  tlsScore:        integer("tls_score").notNull().default(0),
  endpointScore:   integer("endpoint_score").notNull().default(0),
  cloudScore:      integer("cloud_score").notNull().default(0),
  appSecScore:     integer("app_sec_score").notNull().default(0),
  reputationScore: integer("reputation_score").notNull().default(0),
  infoLeakScore:   integer("info_leak_score").notNull().default(0),
  darkWebMentions: integer("dark_web_mentions").notNull().default(0),
  calculatedAt:    timestamp("calculated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorAssetsTable = pgTable("tprm_vendor_assets", {
  id:           serial("id").primaryKey(),
  vendorId:     integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  assetType:    text("asset_type").notNull().default("subdomain"),
  value:        text("value").notNull(),
  riskLevel:    text("risk_level").notNull().default("low"),
  status:       text("status").notNull().default("active"),
  discoveredAt: timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorFindingsTable = pgTable("tprm_vendor_findings", {
  id:          serial("id").primaryKey(),
  vendorId:    integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  title:       text("title").notNull(),
  severity:    text("severity").notNull().default("medium"),
  category:    text("category").notNull().default("misconfiguration"),
  description: text("description"),
  remediation: text("remediation"),
  status:      text("status").notNull().default("open"),
  cvss:        real("cvss"),
  cve:         text("cve"),
  epss:        real("epss"),
  isKev:       boolean("is_kev").notNull().default(false),
  evidence:    jsonb("evidence"),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt:  timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmFourthPartyVendorsTable = pgTable("tprm_fourth_party_vendors", {
  id:               serial("id").primaryKey(),
  parentVendorId:   integer("parent_vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:         integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  name:             text("name").notNull(),
  domain:           text("domain"),
  category:         text("category").notNull().default("infrastructure"),
  riskLevel:        text("risk_level").notNull().default("medium"),
  confidence:       integer("confidence").notNull().default(50),
  isActive:         boolean("is_active").notNull().default(true),
  discoveryMethod:  text("discovery_method").notNull().default("http_header"),
  riskContribution: integer("risk_contribution").notNull().default(0),
  details:          jsonb("details"),
  discoveredAt:     timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorSecurityAnalysisTable = pgTable("tprm_vendor_security_analysis", {
  id:                   serial("id").primaryKey(),
  vendorId:             integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:             integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  securityHeadersScore: integer("security_headers_score").notNull().default(0),
  dnsHealthScore:       integer("dns_health_score").notNull().default(0),
  sslScore:             integer("ssl_score").notNull().default(0),
  cookieScore:          integer("cookie_score").notNull().default(0),
  overallGrade:         text("overall_grade").notNull().default("F"),
  hsts:                 boolean("hsts").notNull().default(false),
  hstsMaxAge:           integer("hsts_max_age"),
  csp:                  boolean("csp").notNull().default(false),
  cspUnsafeInline:      boolean("csp_unsafe_inline").notNull().default(false),
  xFrameOptions:        text("x_frame_options"),
  xContentType:         boolean("x_content_type").notNull().default(false),
  referrerPolicy:       text("referrer_policy"),
  permissionsPolicy:    boolean("permissions_policy").notNull().default(false),
  coep:                 boolean("coep").notNull().default(false),
  coop:                 boolean("coop").notNull().default(false),
  spfRecord:            text("spf_record"),
  spfPolicy:            text("spf_policy"),
  dmarcRecord:          text("dmarc_record"),
  dmarcDisposition:     text("dmarc_disposition"),
  dkimSelectors:        jsonb("dkim_selectors").notNull().default([]),
  caaRecords:           jsonb("caa_records").notNull().default([]),
  dnssec:               boolean("dnssec").notNull().default(false),
  sslProtocol:          text("ssl_protocol"),
  sslGrade:             text("ssl_grade"),
  sslExpiryDays:        integer("ssl_expiry_days"),
  certSanCount:         integer("cert_san_count"),
  openPorts:            jsonb("open_ports").notNull().default([]),
  cookiesSecure:        integer("cookies_secure").notNull().default(0),
  cookiesHttponly:      integer("cookies_httponly").notNull().default(0),
  cookiesSamesite:      integer("cookies_samesite").notNull().default(0),
  totalCookies:         integer("total_cookies").notNull().default(0),
  rawHeaders:           jsonb("raw_headers"),
  scannedAt:            timestamp("scanned_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorBreachEventsTable = pgTable("tprm_vendor_breach_events", {
  id:           serial("id").primaryKey(),
  vendorId:     integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  breachName:   text("breach_name").notNull(),
  breachDate:   text("breach_date"),
  pwnCount:     integer("pwn_count").notNull().default(0),
  dataClasses:  jsonb("data_classes").notNull().default([]),
  description:  text("description"),
  isVerified:   boolean("is_verified").notNull().default(true),
  isSensitive:  boolean("is_sensitive").notNull().default(false),
  isFabricated: boolean("is_fabricated").notNull().default(false),
  logoPath:     text("logo_path"),
  source:       text("source").notNull().default("hibp"),
  rawData:      jsonb("raw_data"),
  discoveredAt: timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmSupplyChainNodesTable = pgTable("tprm_supply_chain_nodes", {
  id:              serial("id").primaryKey(),
  vendorId:        integer("vendor_id").references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  name:            text("name").notNull(),
  version:         text("version"),
  nodeType:        text("node_type").notNull().default("software"),
  cpe:             text("cpe"),
  purl:            text("purl"),
  license:         text("license"),
  supplier:        text("supplier"),
  riskLevel:       text("risk_level").notNull().default("low"),
  vulnerabilities: jsonb("vulnerabilities").default([]),
  parentNodeId:    integer("parent_node_id"),
  depth:           integer("depth").notNull().default(0),
  sbomUploadId:    integer("sbom_upload_id"),
  discoveredAt:    timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorContactsTable = pgTable("tprm_vendor_contacts", {
  id:                      serial("id").primaryKey(),
  vendorId:                integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:                integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  name:                    text("name").notNull(),
  email:                   text("email").notNull(),
  role:                    text("role"),
  isPrimary:               boolean("is_primary").notNull().default(false),
  isEmailVerified:         boolean("is_email_verified").notNull().default(false),
  emailVerifiedAt:         timestamp("email_verified_at", { withTimezone: true }),
  emailVerificationToken:  text("email_verification_token"),
  createdAt:               timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmQuestionnaireTemplatesTable = pgTable("tprm_questionnaire_templates", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  name:        text("name").notNull(),
  description: text("description"),
  category:    text("category").notNull().default("security"),
  questions:   jsonb("questions").notNull().default([]),
  isGlobal:    boolean("is_global").notNull().default(false),
  isActive:    boolean("is_active").notNull().default(true),
  createdBy:   integer("created_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorQuestionnairesTable = pgTable("tprm_vendor_questionnaires", {
  id:           serial("id").primaryKey(),
  vendorId:     integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  templateId:   integer("template_id").references(() => tprmQuestionnaireTemplatesTable.id, { onDelete: "set null" }),
  status:       text("status").notNull().default("draft"),
  sentAt:       timestamp("sent_at", { withTimezone: true }),
  dueDate:      timestamp("due_date", { withTimezone: true }),
  completedAt:  timestamp("completed_at", { withTimezone: true }),
  respondedBy:  text("responded_by"),
  accessToken:  uuid("access_token").notNull().defaultRandom().unique(),
  responses:    jsonb("responses").default([]),
  score:        integer("score"),
  riskLevel:    text("risk_level"),
  notes:        text("notes"),
  createdAt:    timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmComplianceDocumentsTable = pgTable("tprm_compliance_documents", {
  id:               serial("id").primaryKey(),
  vendorId:         integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:         integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  documentType:     text("document_type").notNull(),
  title:            text("title").notNull(),
  auditor:          text("auditor"),
  auditPeriodStart: date("audit_period_start"),
  auditPeriodEnd:   date("audit_period_end"),
  expiresAt:        date("expires_at"),
  status:           text("status").notNull().default("pending_review"),
  coverageScope:    text("coverage_scope"),
  fileData:         text("file_data"),
  fileName:         text("file_name"),
  fileSize:         integer("file_size"),
  uploadedBy:       integer("uploaded_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:        timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:        timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmComplianceRequirementsTable = pgTable("tprm_compliance_requirements", {
  id:           serial("id").primaryKey(),
  vendorId:     integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  documentType: text("document_type").notNull(),
  required:     boolean("required").notNull().default(true),
  dueDate:      date("due_date"),
  reminderDays: integer("reminder_days").notNull().default(30),
  notes:        text("notes"),
  createdAt:    timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmVendorComplianceControlsTable = pgTable("tprm_vendor_compliance_controls", {
  id:           serial("id").primaryKey(),
  vendorId:     integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  framework:    text("framework").notNull(),
  controlId:    text("control_id").notNull(),
  controlTitle: text("control_title").notNull(),
  category:     text("category"),
  status:       text("status").notNull().default("pending_review"),
  evidence:     text("evidence"),
  notes:        text("notes"),
  assignedTo:   text("assigned_to"),
  reviewedAt:   timestamp("reviewed_at", { withTimezone: true }),
  nextReviewAt: timestamp("next_review_at", { withTimezone: true }),
  createdBy:    integer("created_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:    timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:    timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmComplianceRemindersTable = pgTable("tprm_compliance_reminders", {
  id:            serial("id").primaryKey(),
  vendorId:      integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:      integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  title:         text("title").notNull(),
  type:          text("type").notNull().default("custom"),
  referenceId:   integer("reference_id"),
  referenceType: text("reference_type"),
  dueDate:       date("due_date").notNull(),
  notes:         text("notes"),
  isDismissed:   boolean("is_dismissed").notNull().default(false),
  createdBy:     integer("created_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:     timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const tprmSbomUploadsTable = pgTable("tprm_sbom_uploads", {
  id:                      serial("id").primaryKey(),
  vendorId:                integer("vendor_id").notNull().references(() => tprmVendorsTable.id, { onDelete: "cascade" }),
  tenantId:                integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  fileName:                text("file_name").notNull(),
  format:                  text("format").notNull().default("cyclonedx_json"),
  specVersion:             text("spec_version"),
  toolName:                text("tool_name"),
  componentCount:          integer("component_count").notNull().default(0),
  vulnerableComponentCount: integer("vulnerable_component_count").notNull().default(0),
  fileData:                text("file_data"),
  uploadedBy:              integer("uploaded_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:               timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type TprmModuleAssignment         = typeof tprmModuleAssignmentsTable.$inferSelect;
export type TprmVendor                   = typeof tprmVendorsTable.$inferSelect;
export type TprmVendorRiskScore          = typeof tprmVendorRiskScoresTable.$inferSelect;
export type TprmVendorAsset              = typeof tprmVendorAssetsTable.$inferSelect;
export type TprmVendorFinding            = typeof tprmVendorFindingsTable.$inferSelect;
export type TprmFourthPartyVendor        = typeof tprmFourthPartyVendorsTable.$inferSelect;
export type TprmVendorSecurityAnalysis   = typeof tprmVendorSecurityAnalysisTable.$inferSelect;
export type TprmVendorBreachEvent        = typeof tprmVendorBreachEventsTable.$inferSelect;
export type TprmSupplyChainNode          = typeof tprmSupplyChainNodesTable.$inferSelect;
export type TprmVendorContact            = typeof tprmVendorContactsTable.$inferSelect;
export type TprmQuestionnaireTemplate    = typeof tprmQuestionnaireTemplatesTable.$inferSelect;
export type TprmVendorQuestionnaire      = typeof tprmVendorQuestionnairesTable.$inferSelect;
export type TprmComplianceDocument       = typeof tprmComplianceDocumentsTable.$inferSelect;
export type TprmComplianceRequirement       = typeof tprmComplianceRequirementsTable.$inferSelect;
export type TprmVendorComplianceControl     = typeof tprmVendorComplianceControlsTable.$inferSelect;
export type TprmComplianceReminder          = typeof tprmComplianceRemindersTable.$inferSelect;
export type TprmSbomUpload                  = typeof tprmSbomUploadsTable.$inferSelect;

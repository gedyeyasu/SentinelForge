-- SentinelForge Supabase schema for enterprise SaaS multi-tenancy
-- Run this in Supabase SQL editor to create enterprise tables
-- Matches SQLite schema in src/sentinelforge/control/storage.py plus enterprise extensions

-- Enable RLS
-- Orgs
create table if not exists orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text unique not null,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  metadata jsonb default '{}'::jsonb
);

-- Memberships with RBAC
create table if not exists memberships (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references orgs(id) on delete cascade,
  user_id uuid references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','security','viewer')),
  created_at timestamptz default now(),
  unique(org_id, user_id)
);

-- API keys scoped per org
create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references orgs(id) on delete cascade,
  name text not null,
  key_hash text not null unique, -- sha256 of actual key, actual key shown once
  scopes text[] not null default '{read}',
  last_used_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz default now(),
  created_by uuid references auth.users(id)
);

-- Pentest runs (mirror SQLite pentest_runs + enterprise)
create table if not exists pentest_runs (
  run_id text primary key,
  org_id uuid references orgs(id),
  repository text not null,
  scope_file text not null,
  status text not null default 'queued',
  phase text not null default 'scoping',
  candidate_verdict text not null default 'pending',
  mode text not null default 'standard',
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  results_json jsonb,
  error text,
  cost_usd numeric(10,6) default 0,
  token_usage jsonb default '{}'::jsonb
);

-- Events append-only
create table if not exists events (
  sequence bigserial primary key,
  run_id text references pentest_runs(run_id) on delete cascade,
  org_id uuid references orgs(id),
  phase text not null,
  kind text not null,
  occurred_at timestamptz default now(),
  payload_json jsonb not null
);
create index if not exists events_run_sequence on events(run_id, sequence);

-- Security invariants learned
create table if not exists security_invariants (
  id text primary key,
  org_id uuid references orgs(id),
  invariant text not null,
  file_path text not null,
  rule_id text not null,
  first_seen timestamptz default now(),
  last_seen timestamptz default now(),
  count int default 1,
  status text default 'active',
  metadata_json jsonb default '{}'::jsonb
);

-- Target memory for learning delta
create table if not exists target_memory (
  target_id text primary key,
  org_id uuid references orgs(id),
  base_url text not null,
  endpoint_map_json jsonb default '[]'::jsonb,
  role_graph_json jsonb default '{}'::jsonb,
  login_workflow_json jsonb default '{}'::jsonb,
  prior_attacks_json jsonb default '[]'::jsonb,
  successful_payloads_json jsonb default '[]'::jsonb,
  updated_at timestamptz default now(),
  run_count int default 1,
  learning_delta_json jsonb default '{}'::jsonb
);

-- Advisory cursor for heartbeat dedup
create table if not exists advisory_cursor (
  id text primary key,
  org_id uuid references orgs(id),
  last_timestamp timestamptz not null,
  dedup_key text not null,
  advisory_count int default 0,
  source text default 'redhat_csaf',
  payload_json jsonb default '{}'::jsonb,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Agent traces for observability / cost
create table if not exists agent_traces (
  trace_id text primary key,
  run_id text references pentest_runs(run_id) on delete cascade,
  org_id uuid references orgs(id),
  agent_role text not null,
  model text not null,
  provider text not null,
  prompt_template_version text default 'v1',
  input_tokens int,
  output_tokens int,
  latency_ms int,
  retry_count int default 0,
  hiddenlayer_input_verdict text,
  hiddenlayer_output_verdict text,
  tool_call_parse_success boolean default true,
  cost_usd numeric(10,6) default 0,
  created_at timestamptz default now(),
  payload_json jsonb default '{}'::jsonb
);
create index if not exists traces_run_idx on agent_traces(run_id);
create index if not exists traces_role_idx on agent_traces(agent_role);

-- Audit logs immutable (append only, no update/delete via RLS)
create table if not exists audit_logs (
  id bigserial primary key,
  org_id uuid references orgs(id),
  user_id uuid references auth.users(id),
  action text not null,
  resource_type text not null,
  resource_id text not null,
  metadata jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);

-- VEX documents generated per run
create table if not exists vex_documents (
  id uuid primary key default gen_random_uuid(),
  run_id text references pentest_runs(run_id) on delete cascade,
  org_id uuid references orgs(id),
  cve_id text not null,
  status text not null,
  justification text,
  component_name text,
  created_at timestamptz default now(),
  vex_json jsonb not null
);

-- RLS policies (example, tighten for prod)
alter table orgs enable row level security;
alter table memberships enable row level security;
alter table api_keys enable row level security;
alter table pentest_runs enable row level security;
alter table events enable row level security;
alter table security_invariants enable row level security;
alter table target_memory enable row level security;
alter table advisory_cursor enable row level security;
alter table agent_traces enable row level security;
alter table audit_logs enable row level security;
alter table vex_documents enable row level security;

-- Example policy: users can only see their org's data
-- create policy "org isolation" on pentest_runs for select using (org_id in (select org_id from memberships where user_id = auth.uid()));

-- For demo, allow all if not using auth:
-- create policy "allow all for demo" on pentest_runs for all using (true) with check (true);

-- ══════════════════════════════════════════════════════════════════
--  project_locations.sql — Divisões ("Localização na fração") por empreendimento
--  [{pt, en}] em projects.locations; vazio/null = lista padrão da plataforma.
--  Idempotente. Correr ANTES de fazer upload do novo index.html.
-- ══════════════════════════════════════════════════════════════════
alter table projects add column if not exists locations jsonb;

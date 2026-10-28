-- ══════════════════════════════════════════════════════════════════
--  owner_verification.sql — Proprietários por fração + código por email
--
--  ANTES DE CORRER: substituir COLAR_AQUI_A_PRIVATE_KEY (passo 1, abaixo)
--  pela Private Key do EmailJS (Account → API keys → Private Key).
--  Idempotente: pode ser corrido mais do que uma vez.
-- ══════════════════════════════════════════════════════════════════

-- Envio de emails a partir da base de dados (o código nunca passa pelo browser)
create extension if not exists pg_net;

-- ── Configuração privada (sem acesso público) ──
create table if not exists app_settings (
  key   text primary key,
  value text not null
);
alter table app_settings enable row level security;

-- PASSO 1: colar a Private Key do EmailJS entre as plicas
insert into app_settings (key, value) values ('emailjs_private_key', 'COLAR_AQUI_A_PRIVATE_KEY')
on conflict (key) do update set value = excluded.value
where excluded.value <> 'COLAR_AQUI_A_PRIVATE_KEY';

-- ── Proprietários: email ↔ fração (vários emails por fração, várias frações por email) ──
create table if not exists unit_owners (
  id         bigserial primary key,
  project_id bigint not null references projects(id) on delete cascade,
  unit_code  text   not null,
  email      text   not null check (email = lower(trim(email))),
  created_at timestamptz default now(),
  unique (project_id, unit_code, email)
);
create index if not exists unit_owners_email_idx on unit_owners (email);
alter table unit_owners enable row level security;
drop policy if exists "Gestores acesso total" on unit_owners;
create policy "Gestores acesso total" on unit_owners
  for all to authenticated using (true) with check (true);
grant select, insert, update, delete on unit_owners to authenticated;
grant usage, select on sequence unit_owners_id_seq to authenticated;

-- ── Códigos de confirmação e sessões de proprietário (sem acesso público) ──
create table if not exists owner_codes (
  id         bigserial primary key,
  email      text not null,
  code_hash  text not null,
  attempts   int  not null default 0,
  used_at    timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists owner_codes_email_idx on owner_codes (email, created_at desc);
alter table owner_codes enable row level security;

create table if not exists owner_sessions (
  token      uuid primary key default gen_random_uuid(),
  email      text not null,
  expires_at timestamptz not null default now() + interval '90 days',
  created_at timestamptz not null default now()
);
alter table owner_sessions enable row level security;

-- ── Pré-preenchimento: proprietários a partir das ocorrências já existentes ──
insert into unit_owners (project_id, unit_code, email)
select distinct i.project_id, u->>'code', lower(trim(i.client_email))
from issues i
join projects p on p.id = i.project_id
cross join lateral jsonb_array_elements(coalesce(p.units::jsonb, '[]'::jsonb)) u
where coalesce(trim(i.client_email), '') <> ''
  and coalesce(u->>'code', '') <> ''
  and (i.unit = u->>'code'
       or left(i.unit, length(u->>'code') + 3) in ((u->>'code') || ' — ', (u->>'code') || ' · '))
on conflict do nothing;

-- ── Funções auxiliares ──
create or replace function owner_units_json(p_email text)
returns jsonb language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('project_id', project_id, 'unit_code', unit_code)
                            order by project_id, unit_code), '[]'::jsonb)
  from unit_owners where email = lower(trim(p_email));
$$;
revoke execute on function owner_units_json(text) from public, anon, authenticated;

-- 1) Pede código: 'sent' | 'not_found' | 'wait' | 'too_many' | 'not_configured'
create or replace function request_owner_code(p_email text, p_name text default '')
returns text language plpgsql security definer set search_path = public as $$
declare
  v_email text := lower(trim(p_email));
  v_code  text;
  v_key   text;
  v_name  text := coalesce(nullif(trim(p_name), ''), 'Cliente / Client');
begin
  if v_email = '' or not exists (select 1 from unit_owners where email = v_email) then
    return 'not_found';
  end if;
  if exists (select 1 from owner_codes where email = v_email and created_at > now() - interval '60 seconds') then
    return 'wait';
  end if;
  if (select count(*) from owner_codes where email = v_email and created_at > now() - interval '1 hour') >= 5 then
    return 'too_many';
  end if;
  select value into v_key from app_settings where key = 'emailjs_private_key';
  if v_key is null or v_key = 'COLAR_AQUI_A_PRIVATE_KEY' then
    return 'not_configured';
  end if;

  v_code := lpad(((('x' || lpad(substr(md5(gen_random_uuid()::text), 1, 12), 16, '0'))::bit(64)::bigint) % 1000000)::text, 6, '0');
  insert into owner_codes (email, code_hash) values (v_email, encode(sha256(convert_to(v_email || ':' || v_code, 'UTF8')), 'hex'));

  perform net.http_post(
    url     := 'https://api.emailjs.com/api/v1.0/email/send',
    headers := '{"Content-Type":"application/json"}'::jsonb,
    body    := jsonb_build_object(
      'service_id',  'service_mvsu3re',
      'template_id', 'template_nlw44gf',
      'user_id',     '1J_vAQ1k7FzWiKJWO',
      'accessToken', v_key,
      'template_params', jsonb_build_object(
        'to_email',     v_email,
        'client',       v_name,
        'subject_line', 'Código de confirmação ' || v_code || ' | Confirmation code ' || v_code,
        'message_body', 'O seu código de confirmação é: ' || v_code || E'\n\n'
                     || 'Introduza este código no formulário de ocorrências pós-venda. É válido durante 15 minutos. Se não pediu este código, ignore este email.'
                     || E'\n\n— — — English — — —\n\n'
                     || 'Your confirmation code is: ' || v_code || E'\n\n'
                     || 'Enter this code in the after-sales issue form. It is valid for 15 minutes. If you did not request this code, please ignore this email.',
        'unit',         '—',
        'category',     '—',
        'extra_info',   ''
      )
    )
  );
  return 'sent';
end;
$$;

-- 2) Confirma código: {status:'ok', token, email, units} | {status:'invalid'|'expired'|'too_many'}
create or replace function verify_owner_code(p_email text, p_code text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_email text := lower(trim(p_email));
  v_row   owner_codes;
  v_token uuid;
begin
  select * into v_row from owner_codes
   where email = v_email and used_at is null and created_at > now() - interval '15 minutes'
   order by created_at desc limit 1;
  if not found then return jsonb_build_object('status', 'expired'); end if;
  if v_row.attempts >= 5 then return jsonb_build_object('status', 'too_many'); end if;
  if v_row.code_hash <> encode(sha256(convert_to(v_email || ':' || trim(coalesce(p_code, '')), 'UTF8')), 'hex') then
    update owner_codes set attempts = attempts + 1 where id = v_row.id;
    return jsonb_build_object('status', 'invalid');
  end if;
  update owner_codes set used_at = now() where email = v_email and used_at is null;
  delete from owner_sessions where expires_at < now();
  insert into owner_sessions (email) values (v_email) returning token into v_token;
  return jsonb_build_object('status', 'ok', 'token', v_token, 'email', v_email, 'units', owner_units_json(v_email));
end;
$$;

-- 3) Retoma sessão guardada no browser: {status:'ok', email, units} | {status:'invalid'}
create or replace function owner_session(p_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_email text;
begin
  select email into v_email from owner_sessions where token = p_token and expires_at > now();
  if v_email is null then return jsonb_build_object('status', 'invalid'); end if;
  return jsonb_build_object('status', 'ok', 'email', v_email, 'units', owner_units_json(v_email));
end;
$$;

-- 4) Cria ocorrência só se o email confirmado for proprietário da fração
--    (ou de uma fração do mesmo empreendimento, no caso de áreas comuns)
create or replace function create_issue_owner(
  p_token uuid, p_project_id bigint, p_client_name text, p_client_phone text,
  p_unit text, p_category text, p_location text, p_description text,
  p_priority text, p_photo_urls text[]
) returns bigint language plpgsql security definer set search_path = public as $$
declare
  v_email text;
  v_id    bigint;
begin
  select email into v_email from owner_sessions where token = p_token and expires_at > now();
  if v_email is null then raise exception 'invalid_token'; end if;
  if not exists (
    select 1 from unit_owners o
     where o.email = v_email and o.project_id = p_project_id
       and (p_unit like 'AC — %'
            or p_unit = o.unit_code
            or left(p_unit, length(o.unit_code) + 3) in (o.unit_code || ' — ', o.unit_code || ' · '))
  ) then
    raise exception 'not_owner';
  end if;
  execute format('select create_issue(%s, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
                 p_project_id, p_client_name, v_email, coalesce(p_client_phone, ''), p_unit,
                 p_category, coalesce(p_location, ''), p_description, p_priority, p_photo_urls)
    into v_id;
  return v_id;
end;
$$;

revoke execute on function request_owner_code(text, text) from public;
revoke execute on function verify_owner_code(text, text) from public;
revoke execute on function owner_session(uuid) from public;
revoke execute on function create_issue_owner(uuid, bigint, text, text, text, text, text, text, text, text[]) from public;
grant execute on function request_owner_code(text, text) to anon, authenticated;
grant execute on function verify_owner_code(text, text) to anon, authenticated;
grant execute on function owner_session(uuid) to anon, authenticated;
grant execute on function create_issue_owner(uuid, bigint, text, text, text, text, text, text, text, text[]) to anon, authenticated;

-- ── Fecha a porta antiga: create_issue deixa de estar disponível ao público
--    (continua disponível à gestão autenticada, para registar em nome do cliente)
do $$
declare r record;
begin
  for r in select p.oid::regprocedure as sig
             from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname = 'create_issue' loop
    execute format('revoke execute on function %s from public, anon', r.sig);
    execute format('grant execute on function %s to authenticated', r.sig);
  end loop;
end $$;

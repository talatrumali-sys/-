-- تحدّي التوقعات: إعداد قاعدة البيانات (يُنفَّذ مرة واحدة فقط)
create extension if not exists pgcrypto with schema extensions;

create table if not exists users(
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  pass text not null,
  name text not null,
  emoji text not null default '⚽',
  color text not null default '#0f4a2f',
  is_admin boolean not null default false,
  created_at timestamptz not null default now());
create table if not exists sessions(
  token text primary key,
  user_id uuid not null references users(id) on delete cascade,
  created_at timestamptz not null default now());
create table if not exists matches(
  id text primary key, home text not null, away text not null,
  hc text, ac text, comp text, ts bigint not null,
  status text not null default 'open',
  rh int, ra int, first_scorer text, upd bigint);
create table if not exists preds(
  user_id uuid references users(id) on delete cascade,
  match_id text references matches(id) on delete cascade,
  h int, a int, o text, t int, f text,
  primary key(user_id, match_id));
create table if not exists rules(k text primary key, v int not null);
insert into rules(k,v) values('exact',5),('outcome',3),('diff',2),('team',1),('total',2),('first',2)
  on conflict(k) do nothing;

-- الأمان: لا وصول مباشر للجداول إطلاقًا، كل شيء عبر الدوال أدناه
alter table users enable row level security;
alter table sessions enable row level security;
alter table matches enable row level security;
alter table preds enable row level security;
alter table rules enable row level security;
revoke all on users, sessions, matches, preds, rules from anon, authenticated;

create or replace function _auth(t text) returns users
language plpgsql security definer set search_path=public,extensions as $$
declare r users;
begin
  select u.* into r from sessions s join users u on u.id=s.user_id where s.token=t;
  if not found then raise exception 'الجلسة منتهية، سجّل الدخول من جديد'; end if;
  return r;
end$$;

create or replace function _admin(t text) returns users
language plpgsql security definer set search_path=public,extensions as $$
declare r users;
begin
  r := _auth(t);
  if not r.is_admin then raise exception 'للمدير فقط'; end if;
  return r;
end$$;
revoke execute on function _auth(text), _admin(text) from public, anon, authenticated;

create or replace function _newsession(uid uuid) returns text
language plpgsql security definer set search_path=public,extensions as $$
declare tok text := encode(gen_random_bytes(24),'hex');
begin insert into sessions(token,user_id) values(tok,uid); return tok; end$$;
revoke execute on function _newsession(uuid) from public, anon, authenticated;

create or replace function api_register(p_username text,p_password text,p_name text,p_emoji text)
returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare uname text := lower(trim(coalesce(p_username,''))); u users;
begin
  if uname !~ '^[a-z0-9_.]{3,20}$' then raise exception 'اسم المستخدم: من 3 إلى 20 حرفًا إنجليزيًا أو أرقامًا'; end if;
  if length(coalesce(p_password,''))<6 then raise exception 'كلمة المرور 6 أحرف على الأقل'; end if;
  if exists(select 1 from users where username=uname) then raise exception 'اسم المستخدم مستخدم من قبل'; end if;
  insert into users(username,pass,name,emoji,color,is_admin)
  values(uname, crypt(p_password, gen_salt('bf')),
    left(coalesce(nullif(trim(p_name),''),uname),20), left(coalesce(nullif(p_emoji,''),'⚽'),8),
    (array['#8b1a1a','#0f4a2f','#1e3a8a','#b8860b','#5b2a86','#0e7490'])[1+floor(random()*6)::int],
    not exists(select 1 from users))
  returning * into u;
  return jsonb_build_object('token',_newsession(u.id));
end$$;

create or replace function api_login(p_username text,p_password text)
returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare u users;
begin
  select * into u from users where username=lower(trim(coalesce(p_username,''))) and pass=crypt(coalesce(p_password,''),pass);
  if not found then perform pg_sleep(0.4); raise exception 'اسم المستخدم أو كلمة المرور غير صحيحة'; end if;
  return jsonb_build_object('token',_newsession(u.id));
end$$;

create or replace function api_logout(p_token text) returns void
language sql security definer set search_path=public,extensions as $$
  delete from sessions where token=p_token;
$$;

create or replace function api_update_profile(p_token text,p_name text,p_emoji text) returns void
language plpgsql security definer set search_path=public,extensions as $$
declare u users := _auth(p_token);
begin
  update users set name=left(coalesce(nullif(trim(p_name),''),name),20), emoji=left(coalesce(nullif(p_emoji,''),emoji),8) where id=u.id;
end$$;

create or replace function api_state(p_token text) returns jsonb
language plpgsql security definer set search_path=public,extensions as $$
declare u users := _auth(p_token); nowms bigint := (extract(epoch from now())*1000)::bigint;
begin
  return jsonb_build_object(
    'me', jsonb_build_object('id',u.id,'username',u.username,'name',u.name,'emoji',u.emoji,'color',u.color,'is_admin',u.is_admin),
    'players', coalesce((select jsonb_agg(jsonb_build_object('id',x.id,'name',x.name,'emoji',x.emoji,'color',x.color) order by x.created_at) from users x),'[]'::jsonb),
    'matches', coalesce((select jsonb_agg(jsonb_build_object('id',m.id,'home',m.home,'away',m.away,'hc',m.hc,'ac',m.ac,'comp',m.comp,'ts',m.ts,'status',m.status,'rh',m.rh,'ra',m.ra,'first',m.first_scorer,'upd',m.upd)) from matches m),'[]'::jsonb),
    -- توقعات الآخرين لا تُرسل إلا بعد إغلاق المباراة
    'preds', coalesce((select jsonb_agg(jsonb_build_object('user_id',p.user_id,'match_id',p.match_id,'h',p.h,'a',p.a,'o',p.o,'t',p.t,'f',p.f))
        from preds p join matches m on m.id=p.match_id where p.user_id=u.id or m.status<>'open' or m.ts<=nowms),'[]'::jsonb),
    'rules', coalesce((select jsonb_object_agg(k,v) from rules),'{}'::jsonb));
end$$;

create or replace function api_save_pred(p_token text,p_match text,p_h int,p_a int,p_o text,p_t int,p_f text) returns void
language plpgsql security definer set search_path=public,extensions as $$
declare u users := _auth(p_token); m matches; nowms bigint := (extract(epoch from now())*1000)::bigint;
begin
  select * into m from matches where id=p_match;
  if not found then raise exception 'المباراة غير موجودة'; end if;
  if m.status<>'open' or m.ts<=nowms then raise exception 'أُغلقت التوقعات لهذه المباراة'; end if;
  if coalesce(p_h,0)<0 or coalesce(p_a,0)<0 or coalesce(p_t,0)<0 or coalesce(p_h,0)>30 or coalesce(p_a,0)>30 or coalesce(p_t,0)>60 then raise exception 'قيمة غير صالحة'; end if;
  if (p_h is null) <> (p_a is null) then raise exception 'أدخل نتيجة الفريقين معًا'; end if;
  if p_o is not null and p_o not in ('h','d','a') then raise exception 'قيمة غير صالحة'; end if;
  if p_f is not null and p_f not in ('h','a','n') then raise exception 'قيمة غير صالحة'; end if;
  insert into preds(user_id,match_id,h,a,o,t,f) values(u.id,p_match,p_h,p_a,p_o,p_t,p_f)
  on conflict(user_id,match_id) do update set h=excluded.h,a=excluded.a,o=excluded.o,t=excluded.t,f=excluded.f;
end$$;

create or replace function api_save_match(p_token text,p_m jsonb) returns void
language plpgsql security definer set search_path=public,extensions as $$
declare u users := _admin(p_token);
begin
  insert into matches(id,home,away,hc,ac,comp,ts,status,rh,ra,first_scorer,upd)
  values(p_m->>'id',p_m->>'home',p_m->>'away',p_m->>'hc',p_m->>'ac',p_m->>'comp',(p_m->>'ts')::bigint,
         coalesce(p_m->>'status','open'),(p_m->>'rh')::int,(p_m->>'ra')::int,p_m->>'first',(p_m->>'upd')::bigint)
  on conflict(id) do update set home=excluded.home,away=excluded.away,hc=excluded.hc,ac=excluded.ac,comp=excluded.comp,
    ts=excluded.ts,status=excluded.status,rh=excluded.rh,ra=excluded.ra,first_scorer=excluded.first_scorer,upd=excluded.upd;
end$$;

create or replace function api_delete_match(p_token text,p_id text) returns void
language plpgsql security definer set search_path=public,extensions as $$
declare u users := _admin(p_token);
begin delete from matches where id=p_id; end$$;

create or replace function api_save_rules(p_token text,p_rules jsonb) returns void
language plpgsql security definer set search_path=public,extensions as $$
declare u users := _admin(p_token); kk text;
begin
  foreach kk in array array['exact','outcome','diff','team','total','first'] loop
    if p_rules ? kk then insert into rules(k,v) values(kk,greatest(0,least(100,(p_rules->>kk)::int)))
      on conflict(k) do update set v=excluded.v; end if;
  end loop;
end$$;

revoke execute on function api_register(text,text,text,text), api_login(text,text), api_logout(text),
  api_update_profile(text,text,text), api_state(text), api_save_pred(text,text,int,int,text,int,text),
  api_save_match(text,jsonb), api_delete_match(text,text), api_save_rules(text,jsonb) from public;

grant execute on function api_register(text,text,text,text), api_login(text,text), api_logout(text),
  api_update_profile(text,text,text), api_state(text), api_save_pred(text,text,int,int,text,int,text),
  api_save_match(text,jsonb), api_delete_match(text,text), api_save_rules(text,jsonb) to anon, authenticated;

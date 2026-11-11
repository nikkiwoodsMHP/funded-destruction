const out=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
const err=(message,status=400)=>out({error:message},status);
const statuses=new Set(["new","screening","verifying","investigating","closed"]);
const categories=new Set(["Water, air or soil pollution","Deforestation or habitat loss","Mining or industrial extraction","Conflict-related environmental harm","Financial or procurement records","Other environmental concern"]);
const clean=(x,n)=>typeof x==="string"?x.trim().slice(0,n+1):"";
const urlOK=(v)=>{try{let u=new URL(v);return ["https:","http:"].includes(u.protocol)}catch{return false}};
const bytes=(s)=>new TextEncoder().encode(s);
const decode64=(s)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(s.length/4)*4,"=")),x=>x.charCodeAt(0));
const decode=(s)=>new TextDecoder().decode(decode64(s));
const security={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"};
async function parse(req){
 if(!req.headers.get("content-type")?.includes("application/json"))return null;
 if(Number(req.headers.get("content-length")||0)>12000)return null;
 const s=await req.text();if(bytes(s).byteLength>12000)return null;
 try{return JSON.parse(s)}catch{return null}
}
async function access(req,env){
 const jwt=req.headers.get("Cf-Access-Jwt-Assertion");
 if(!jwt||!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD||!env.EDITOR_EMAILS)return null;
 const [h,p,s]=jwt.split(".");if(!h||!p||!s)return null;
 let header,payload;try{header=JSON.parse(decode(h));payload=JSON.parse(decode(p))}catch{return null}
 if(header.alg!=="RS256"||!header.kid)return null;
 const domain=env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//,"").replace(/\/$/,"");
 if(!/^[a-zA-Z0-9.-]+\.cloudflareaccess\.com$/.test(domain))return null;
 const now=Math.floor(Date.now()/1000);
 if(payload.iss!=="https://"+domain||!Array.isArray(payload.aud)||!payload.aud.includes(env.ACCESS_AUD)||typeof payload.exp!=="number"||payload.exp<=now||typeof payload.iat!=="number"||payload.iat>now+60)return null;
 const email=clean(payload.email,250).toLowerCase();
 if(!env.EDITOR_EMAILS.split(",").map(x=>x.trim().toLowerCase()).includes(email))return null;
 try{
  const response=await fetch("https://"+domain+"/cdn-cgi/access/certs");
  if(!response.ok)return null;
  const keys=await response.json(),jwk=(keys.keys||[]).find(x=>x.kid===header.kid&&x.kty==="RSA");
  if(!jwk)return null;
  const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
  return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,decode64(s),bytes(h+"."+p))?email:null;
 }catch{return null}
}
async function verifiedTurnstile(req,env,token){
 if(!env.TURNSTILE_SECRET||!token)return false;
 try{
  const body=new URLSearchParams({secret:env.TURNSTILE_SECRET,response:token});
  const ip=req.headers.get("CF-Connecting-IP");if(ip)body.set("remoteip",ip);
  const r=await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",{method:"POST",body});
  return r.ok&&(await r.json()).success===true;
 }catch{return false}
}

async function api(req,env,path,u){


 if(req.method==="GET"&&path==="/api/health"){
  let database_status="unbound";
  if(env.FD_DB){
   try{
    const tables=await env.FD_DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('companies','sources','financial_records','relationships','evidence_reports','editorial_audit')").all();
    const found=new Set((tables.results||[]).map(row=>row.name));
    database_status=found.size===6?"ready":found.size===0?"schema_missing":"schema_incomplete";
   }catch{database_status="unavailable";}
  }
  return out({service:"funded-destruction",database_connected:database_status==="ready",database_status,intake_enabled:env.INTAKE_ENABLED==="true"&&database_status==="ready"&&!!env.TURNSTILE_SECRET&&!!env.TURNSTILE_SITE_KEY});
 }
 if(req.method==="GET"&&path==="/api/config")return out({intake_enabled:env.INTAKE_ENABLED==="true"&&!!env.TURNSTILE_SECRET&&!!env.TURNSTILE_SITE_KEY,turnstile_site_key:env.TURNSTILE_SITE_KEY||null});
 const editor=path.startsWith("/api/editor/")?await access(req,env):null;
 if(path.startsWith("/api/editor/")&&!editor)return err("Unauthorized",401);
 if(!env.FD_DB)return err("Database not configured",503);
 try{
  const schema=await env.FD_DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('companies','sources','financial_records','relationships','evidence_reports','editorial_audit')").all();
  if((schema.results||[]).length!==6)return err("Database schema incomplete",503);
 }catch{return err("Database temporarily unavailable",503)}
 try{
 if(req.method==="GET"&&path==="/api/companies"){
  const q=clean(u.searchParams.get("q"),80);
  const rows=q?await env.FD_DB.prepare("SELECT slug,name,sector FROM companies WHERE name LIKE ? ORDER BY name LIMIT 100").bind("%"+q+"%").all():await env.FD_DB.prepare("SELECT slug,name,sector FROM companies ORDER BY name LIMIT 100").all();
  return out({companies:rows.results,note:"Listing does not imply misconduct."});
 }
 const cm=path.match(/^\/api\/companies\/([a-z0-9-]+)\/?$/);
 if(req.method==="GET"&&cm){
  const company=await env.FD_DB.prepare("SELECT * FROM companies WHERE slug=?").bind(cm[1]).first();
  if(!company)return err("Company not found",404);
  const records=await env.FD_DB.prepare("SELECT f.category,f.record_type,f.description,f.recipient_name,f.amount,f.currency,f.period_start,f.period_end,f.evidence_level,s.title AS source_title,s.publisher,s.url AS source_url,s.publication_date FROM financial_records f JOIN sources s ON f.source_id=s.id WHERE f.company_id=? AND f.review_status='approved' AND s.status='approved' ORDER BY f.id DESC LIMIT 200").bind(company.id).all();
  const links=await env.FD_DB.prepare("SELECT r.target_name,r.relationship_type,r.description,s.url AS source_url FROM relationships r JOIN sources s ON r.source_id=s.id WHERE r.company_id=? AND r.review_status='approved' AND s.status='approved' LIMIT 200").bind(company.id).all();
  return out({company,records:records.results,relationships:links.results,approved_only:true});
 }
 if(req.method==="POST"&&path==="/api/reports"){
  if(env.INTAKE_ENABLED!=="true"||!env.TURNSTILE_SITE_KEY||!env.TURNSTILE_SECRET)return err("Reporting is not open",503);
  const data=await parse(req);if(!data||typeof data!=="object")return err("Invalid JSON");
  if(data.website)return err("Submission rejected");
  const category=clean(data.category,100),location=clean(data.location,160),period=clean(data.period,100),description=clean(data.description,4000),source=clean(data.source,600);
  if(!categories.has(category)||location.length<2||location.length>160||period.length>100||description.length<40||description.length>4000||source&&(!urlOK(source)||source.length>600)||data.consent!==true)return err("Please complete the required fields");
  if(!await verifiedTurnstile(req,env,data.turnstileToken))return err("Verification failed",403);
  const id=crypto.randomUUID();
  await env.FD_DB.prepare("INSERT INTO evidence_reports(id,category,general_location,incident_period,description,public_source_url) VALUES(?,?,?,?,?,?)").bind(id,category,location,period||null,description,source||null).run();
  return out({received:true,reference:id.slice(0,8),message:"Received for private screening; publication is not guaranteed."},201);
 }
 if(path.startsWith("/api/editor/")){
  if(req.method==="GET"&&path==="/api/editor/reports"){
   const status=u.searchParams.get("status")||"new";if(!statuses.has(status))return err("Invalid status");
   const rows=await env.FD_DB.prepare("SELECT id,category,general_location,incident_period,description,public_source_url,submitted_at,status,review_notes,updated_at FROM evidence_reports WHERE status=? ORDER BY submitted_at DESC LIMIT 50").bind(status).all();
   return out({reports:rows.results,status});
  }
  const m=path.match(/^\/api\/editor\/reports\/([a-f0-9-]{36})$/);
  if(req.method==="PATCH"&&m){
   const data=await parse(req);if(!data)return err("Invalid JSON");
   const next=clean(data.status,30),notes=clean(data.notes,4000);
   if(!statuses.has(next)||notes.length>4000)return err("Invalid status");
   const current=await env.FD_DB.prepare("SELECT status FROM evidence_reports WHERE id=?").bind(m[1]).first();
   if(!current)return err("Report not found",404);
   await env.FD_DB.batch([
    env.FD_DB.prepare("UPDATE evidence_reports SET status=?,review_notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(next,notes,m[1]),
    env.FD_DB.prepare("INSERT INTO editorial_audit(report_id,editor_email,action,previous_status,new_status) VALUES(?,?,?,?,?)").bind(m[1],editor,"update_status",current.status,next)
   ]);
   return out({updated:true});
  }
  return err("Not found",404);
 }
 return err("Not found",404);
 }catch{return err("Database operation unavailable",500)}
}
export default {async fetch(req,env){
 const u=new URL(req.url),path=u.pathname;
 if(path.startsWith("/api/"))return api(req,env,path,u);
 if(path.startsWith("/editor/")){
  if(!await access(req,env))return new Response("Verified Cloudflare Access login required",{status:401,headers:security});
  const r=await env.ASSETS.fetch(req),h=new Headers(r.headers);Object.entries(security).forEach(([k,v])=>h.set(k,v));return new Response(r.body,{status:r.status,headers:h});
 }
 return env.ASSETS.fetch(req);
}};
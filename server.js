require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BUCKET = process.env.SUPABASE_BUCKET || 'pvwatch';
const MAX_FILE = 50 * 1024 * 1024;
const SESSION_AGE = 7 * 24 * 60 * 60;

for (const key of ['SUPABASE_URL','SUPABASE_SERVICE_ROLE_KEY','ADMIN_PASSWORD','SESSION_SECRET']) {
  if (!process.env[key]) { console.error(`Missing ${key} in .env`); process.exit(1); }
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'blob:', 'https://*.supabase.co'],
      mediaSrc: ["'self'", 'blob:', 'https://*.supabase.co'],
      connectSrc: ["'self'", 'https://*.supabase.co'],
      fontSrc: ["'self'", 'data:'],
      workerSrc: ["'self'", 'blob:']
    }
  },
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  for (const pair of raw.split(';')) {
    const i = pair.indexOf('=');
    if (i > -1) out[pair.slice(0,i).trim()] = decodeURIComponent(pair.slice(i+1).trim());
  }
  return out;
}
function sign(value) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('hex');
}
function makeSession() {
  const payload = `${Date.now()}:${crypto.randomBytes(24).toString('hex')}`;
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload)}`;
}
function validSession(req) {
  const token = parseCookies(req).pv_session;
  if (!token) return false;
  const [encoded, sig] = token.split('.');
  if (!encoded || !sig) return false;
  const payload = Buffer.from(encoded, 'base64url').toString('utf8');
  const [created] = payload.split(':');
  if (!created || Date.now() - Number(created) > SESSION_AGE * 1000) return false;
  const expected = sign(payload);
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}
function requireAuth(req,res,next) {
  if (!validSession(req)) return res.status(401).json({ error: 'Authentication required' });
  next();
}
function sendPage(name) { return (req,res) => res.sendFile(path.join(__dirname,'public',name)); }
function cleanName(name) {
  return String(name || 'video').replace(/[^\w.()'&$@=;:+?,!\- ]+/g,'_').replace(/\s+/g,' ').trim().slice(0,120);
}
function safeId() { return crypto.randomUUID(); }
async function signedUrl(pathname, expires=3600) {
  if (!pathname) return null;
  const { data, error } = await supabase.storage.from(BUCKET).createSignedUrl(pathname, expires);
  if (error) throw error;
  return data.signedUrl;
}
async function withAssetUrls(row) {
  return {
    ...row,
    thumbnail_url: await signedUrl(row.thumbnail_path, 3600),
    url: null
  };
}

app.post('/api/auth/login', (req,res) => {
  const { password } = req.body || {};
  const a = Buffer.from(String(password || ''));
  const b = Buffer.from(String(process.env.ADMIN_PASSWORD));
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({error:'Invalid password'});
  const token = makeSession();
  res.setHeader('Set-Cookie', `pv_session=${encodeURIComponent(token)}; Max-Age=${SESSION_AGE}; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ok:true});
});
app.post('/api/auth/logout', (req,res) => {
  res.setHeader('Set-Cookie','pv_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');
  res.json({ok:true});
});
app.get('/api/auth/me', (req,res) => res.json({authenticated: validSession(req)}));

app.get('/api/videos', async (req,res) => {
  try {
    const { data, error } = await supabase.from('videos').select('id,title,description,original_name,thumbnail_path,mime_type,size_bytes,duration_seconds,width,height,view_count,created_at').order('created_at',{ascending:false});
    if (error) throw error;
    const rows = await Promise.all((data || []).map(withAssetUrls));
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({error:'Could not load videos'}); }
});

app.get('/api/videos/:id', async (req,res) => {
  try {
    const { data, error } = await supabase.from('videos').select('*').eq('id',req.params.id).single();
    if (error) return res.status(404).json({error:'Video not found'});
    const [url, thumbnail_url, subtitle_url] = await Promise.all([
      signedUrl(data.storage_path, 3600), signedUrl(data.thumbnail_path, 3600), signedUrl(data.subtitle_path, 3600)
    ]);
    res.json({...data,url,thumbnail_url,subtitle_url});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not load video'}); }
});

app.post('/api/videos/:id/view', async (req,res) => {
  try {
    const { data: current, error: findError } = await supabase.from('videos').select('view_count').eq('id',req.params.id).single();
    if (findError) return res.status(404).json({error:'Video not found'});
    const next = Number(current.view_count || 0) + 1;
    const { error } = await supabase.from('videos').update({view_count: next}).eq('id',req.params.id);
    if (error) throw error;
    res.json({view_count: next});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not count view'}); }
});

app.get('/api/dashboard/stats', requireAuth, async (req,res) => {
  try {
    const { data, error } = await supabase.from('videos').select('id,size_bytes,view_count,created_at,title').order('created_at',{ascending:false});
    if (error) throw error;
    const rows = data || [];
    const storage = rows.reduce((s,v)=>s + Number(v.size_bytes||0),0);
    const views = rows.reduce((s,v)=>s + Number(v.view_count||0),0);
    res.json({totalVideos:rows.length,totalStorage:storage,totalViews:views,latest:rows[0]||null});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not load dashboard'}); }
});

app.post('/api/uploads/sign', async (req,res) => {
  try {
    const { kind, filename, mimeType, sizeBytes } = req.body || {};
    const size = Number(sizeBytes);
    if (!['video','thumbnail','subtitle'].includes(kind)) return res.status(400).json({error:'Invalid upload kind'});
    if (!filename || !mimeType || !Number.isFinite(size)) return res.status(400).json({error:'Missing upload details'});
    if (kind === 'video' && !mimeType.startsWith('video/')) return res.status(400).json({error:'Only videos are allowed'});
    if (kind === 'thumbnail' && mimeType !== 'image/jpeg') return res.status(400).json({error:'Thumbnail must be JPEG'});
    if (kind === 'subtitle' && mimeType !== 'text/vtt') return res.status(400).json({error:'Subtitle must be VTT'});
    if (size > MAX_FILE) return res.status(413).json({error:'Free-tier limit: maximum file size is 50 MB'});
    const prefix = kind === 'video' ? 'videos' : kind === 'thumbnail' ? 'thumbnails' : 'subtitles';
    const storagePath = `${prefix}/${new Date().toISOString().slice(0,10)}/${safeId()}-${cleanName(filename)}`;
    const { data, error } = await supabase.storage.from(BUCKET).createSignedUploadUrl(storagePath);
    if (error) throw error;
    res.json({storagePath,token:data.token,signedUrl:data.signedUrl});
  } catch(e) { console.error(e); res.status(500).json({error:e.message || 'Could not sign upload'}); }
});

app.post('/api/videos', async (req,res) => {
  try {
    const {id,title,description,original_name,storage_path,thumbnail_path,subtitle_path,mime_type,size_bytes,duration_seconds,width,height} = req.body || {};
    if (!id || !title || !original_name || !storage_path || !mime_type) return res.status(400).json({error:'Missing video metadata'});
    const { data, error } = await supabase.from('videos').insert([{
      id, title:String(title).slice(0,200), description:String(description||'').slice(0,5000), original_name:String(original_name).slice(0,255),
      storage_path, thumbnail_path:thumbnail_path||null, subtitle_path:subtitle_path||null, mime_type,
      size_bytes:Number(size_bytes)||0, duration_seconds:Number.isFinite(Number(duration_seconds))?Number(duration_seconds):null,
      width:Number(width)||null, height:Number(height)||null
    }]).select().single();
    if (error) throw error;
    res.json({ok:true,video:data});
  } catch(e) { console.error(e); res.status(500).json({error:e.message || 'Could not save video'}); }
});

app.delete('/api/videos/:id', requireAuth, async (req,res) => {
  try {
    const { data, error } = await supabase.from('videos').select('storage_path,thumbnail_path,subtitle_path').eq('id',req.params.id).single();
    if (error) return res.status(404).json({error:'Video not found'});
    const paths=[data.storage_path,data.thumbnail_path,data.subtitle_path].filter(Boolean);
    if (paths.length) { const {error:removeError}=await supabase.storage.from(BUCKET).remove(paths); if(removeError) throw removeError; }
    const {error:dbError}=await supabase.from('videos').delete().eq('id',req.params.id);
    if(dbError) throw dbError;
    res.json({ok:true});
  } catch(e) { console.error(e); res.status(500).json({error:e.message||'Could not delete video'}); }
});

app.get('/', sendPage('home.html'));
app.get('/login', sendPage('login.html'));
app.get('/dashboard', sendPage('dashboard.html'));
app.get('/upload', sendPage('upload.html'));
app.get('/library', sendPage('library.html'));
app.get('/watch/:id', sendPage('watch.html'));

app.listen(PORT,'0.0.0.0',()=>console.log(`PVwatch running on http://localhost:${PORT}`));

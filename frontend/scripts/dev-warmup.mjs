// Dev warmup: ping routes via the Next.js internal server after dev starts
// This file is required by next.config.mjs (dev server hook)
import http from 'http'

const PAGES = (
  process.env.WARMUP_PAGES || '/, /login, /register, /dashboard, /tickets'
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

function wait(ms) {
  return new Promise((res) => setTimeout(res, ms))
}

async function ping(url) {
  return new Promise((resolve) => {
    const req = http.request(url, { method: 'GET' }, (res) => {
      res.resume()
      resolve({ url, status: res.statusCode })
    })
    req.on('error', () => resolve({ url, status: 'ERR' }))
    req.end()
  })
}

export async function runWarmup() {
  const port = process.env.PORT || 3000
  const base = `http://localhost:${port}`
  // Give Next a brief moment to bind
  await wait(800)
  const results = []
  for (const p of PAGES) {
    const res = await ping(`${base}${p}`)
    results.push(res)
  }
  // eslint-disable-next-line no-console
  console.log('[warmup] done:', results)
}

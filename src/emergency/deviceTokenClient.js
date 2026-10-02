// Client-side Device Registration Helper
// Obtains and caches a signed device token from /api/device/register

const TOKEN_KEY = 'saferoute_device_token';

export async function getOrRegisterDeviceToken() {
  if (typeof window === 'undefined') return null;

  try {
    const existing = localStorage.getItem(TOKEN_KEY);
    if (existing && existing.includes('.')) {
      return existing;
    }

    const res = await fetch('/api/device/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });

    if (res.ok) {
      const data = await res.json();
      if (data?.token) {
        localStorage.setItem(TOKEN_KEY, data.token);
        return data.token;
      }
    }
  } catch (err) {
    console.warn('Failed to retrieve device token:', err.message);
  }
  return null;
}

// TODO: Verifier needs to be random string. Can call generateRandomString()
// Store in cookie, then load in callback handler
const verifier = 'random_string_between_43_and_128_characters_long'
const clientId = '5ae5e79b2e80418da0e233e415fe236b'

// Convenience fetch wrapper to auto call .json() on the response
const $fetch = async (...args) => (await fetch(...args)).json()

function sha256(plain) { // returns promise ArrayBuffer
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest('SHA-256', data);
}

function base64urlencode(a) {
  var str = "";
  var bytes = new Uint8Array(a);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function challenge_from_verifier(v) {
  hashed = await sha256(v);
  base64encoded = base64urlencode(hashed);
  return base64encoded;
}

function generateRandomString() {
  function dec2hex(dec) {
    return ('0' + dec.toString(16)).substr(-2)
  }
  var array = new Uint32Array(56/2);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
}

function setCookie(name, value, seconds) {
  var expires = "";
  if (seconds) {
      var date = new Date();
      date.setTime(date.getTime() + (seconds * 1000));
      expires = "; expires=" + date.toUTCString();
  }
  document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}

function getCookie(name) {
  var nameEQ = name + "=";
  var ca = document.cookie.split(';');
  for(var i=0;i < ca.length;i++) {
      var c = ca[i];
      while (c.charAt(0)==' ') c = c.substring(1,c.length);
      if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
  }
  return null;
}

function eraseCookie(name) {
  document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

async function getAuthUrl() {
  const challenge = await challenge_from_verifier(verifier)

  const authUri = new URL('https://accounts.spotify.com/authorize')
  authUri.searchParams.append('client_id', clientId)
  authUri.searchParams.append('response_type','code')
  authUri.searchParams.append('redirect_uri','http://localhost:3000')
  authUri.searchParams.append('code_challenge_method','S256')
  authUri.searchParams.append('code_challenge',challenge)
  authUri.searchParams.append('state','anything')
  authUri.searchParams.append('scope','app-remote-control streaming user-read-playback-state')

  return authUri.toString()
}

function getFormUrlEncodedParams(obj) {
  return Object.entries(obj)
    .map(([key, val]) => {
      return encodeURIComponent(key) + '=' + encodeURIComponent(val)
    })
    .join('&')
}

async function handleCallback() {
  const url = new URL(window.location)
  const code = url.searchParams.get('code')

  if (!code) return false

  const { access_token, expires_in, refresh_token } = await $fetch(
    'https://accounts.spotify.com/api/token',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: getFormUrlEncodedParams({
        client_id: clientId,
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:3000',
        code_verifier: verifier
      })
    }
  )

  if (!access_token) return false
  setCookie('spotifyaccesstoken', access_token, expires_in)
  setCookie('spotifyrefreshtoken', refresh_token)
  return true
}

async function refreshAccessToken(refreshToken) {
  const { access_token, expires_in, refresh_token } = await $fetch(
    'https://accounts.spotify.com/api/token',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: getFormUrlEncodedParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId
      })
    }
  )

  if (!access_token) return false

  setCookie('spotifyaccesstoken', access_token, expires_in)
  setCookie('spotifyrefreshtoken', refresh_token)

  return true
}

async function handleAuth() {
  await handleCallback()
  const accessToken = getCookie('spotifyaccesstoken')

  if (!accessToken) {
    const refreshToken = getCookie('spotifyrefreshtoken')

    let success = false

    if (refreshToken) {
      success = await refreshAccessToken(refreshToken)
      if (success) {
        return getCookie('spotifyaccesstoken')
      }
    }
    if (!success) {
      const authUrl = await getAuthUrl()
      console.log(authUrl)
      window.location.replace(authUrl)
    }
  }

  return accessToken
}


async function run() {
    const accessToken = await handleAuth()
    console.log(accessToken)

    const devices = await $fetch('https://api.spotify.com/v1/me/player/devices', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    })

    console.log(devices)
}

run()

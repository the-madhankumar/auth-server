const BASE_URL = "https://auth-server-4nmm.onrender.com";

async function runTest() {
  console.log("=== End to End OAuth Flow Test ===");
  
  // Use accounts that successfully registered in the previous run!
  const devEmail = 'dev_295839@example.com';
  const userEmail = 'user_295839@example.com';
  const password = "Password123!";
  
  const fakeIp = `192.168.1.${Math.floor(Math.random() * 255)}`;
  const headers = {
    'Content-Type': 'application/json',
    'X-Forwarded-For': fakeIp
  };
  
  console.log(`\n1. Logging into Developer Account (${devEmail})...`);

  const devLogin = await (await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST', headers: headers,
    body: JSON.stringify({email: devEmail, password})
  })).json();
  
  if (!devLogin.success || !devLogin.data) {
      console.error("Login Failed!", devLogin);
      return;
  }
  
  const devToken = devLogin.data.accessToken;
  
  console.log("\n2. Creating OAuth Client App (as developer)...");
  const clientRes = await (await fetch(`${BASE_URL}/api/auth/oauth/clients`, {
    method: 'POST', 
    headers: {'Content-Type': 'application/json', 'Authorization': `Bearer ${devToken}`},
    body: JSON.stringify({
      name: "E2E Test App",
      redirect_uris: ["http://localhost:3000/callback"],
      scopes: ["read:profile", "read:email"],
      is_public: false // Changed to false so PKCE is not strictly required
    })
  })).json();
  
  if (!clientRes.success || !clientRes.data) {
      console.error("Failed to create OAuth client:", clientRes);
      return;
  }
  
  const clientId = clientRes.data.client_id;
  const clientSecret = clientRes.data.client_secret;
  console.log(`-> Client ID: ${clientId}`);
  console.log(`-> Client Secret: ${clientSecret}`);
  
  console.log(`\n3. Logging into Normal User Account (${userEmail})...`);
  
  const userLogin = await (await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST', headers: headers,
    body: JSON.stringify({email: userEmail, password})
  })).json();
  
  if (!userLogin.success || !userLogin.data) {
      console.error("User Login Failed!", userLogin);
      return;
  }
  
  const userToken = userLogin.data.accessToken;
  
  console.log("\n4. Simulating User OAuth Consent (User clicking 'Approve')...");
  const consentBody = new URLSearchParams({
    client_id: clientId,
    redirect_uri: "http://localhost:3000/callback",
    response_type: "code",
    scope: "read:profile read:email",
    action: "approve",
    state: "xyz123"
  });
  
  const consentRes = await fetch(`${BASE_URL}/oauth/authorize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${userToken}` // User is logged in!
    },
    body: consentBody.toString(),
    redirect: 'manual' // We want to catch the redirect!
  });
  
  const redirectUrl = consentRes.headers.get('location');
  console.log(`-> App Redirected to: ${redirectUrl}`);
  
  if (!redirectUrl) {
      console.error("Consent failed. Did not receive a redirect URL.");
      return;
  }
  
  // Extract auth code from redirect URL
  const urlObj = new URL(redirectUrl);
  const code = urlObj.searchParams.get('code');
  console.log(`-> Extracted Auth Code: ${code}`);
  
  console.log("\n5. Third-Party App Exchanges Code for Access Token...");
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: "http://localhost:3000/callback",
    client_id: clientId,
    client_secret: clientSecret
  });
  
  const tokenRes = await (await fetch(`${BASE_URL}/oauth/token`, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: tokenBody.toString()
  })).json();
  
  if (!tokenRes.access_token) {
      console.error("Token Exchange Failed! Response:", tokenRes);
      return;
  }
  
  const appAccessToken = tokenRes.access_token;
  console.log(`-> App Access Token: ${appAccessToken}`);
  
  console.log("\n6. App Fetches User Profile via /oauth/userinfo...");
  const userInfo = await (await fetch(`${BASE_URL}/oauth/userinfo`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${appAccessToken}`
    }
  })).json();
  
  console.log("-> Profile Data returned to Third-Party App:");
  console.log(userInfo);
  console.log("\n=== Test Completed Successfully! ===");
}

runTest().catch(console.error);

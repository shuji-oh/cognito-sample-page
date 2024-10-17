// Cognito設定
const REGION = 'ap-northeast-1';  // Cognitoが配置されているリージョン
const CLIENT_ID = '<client id>';  // CognitoユーザープールのクライアントID

AWS.config.region = REGION;

// DOMの読み込みが完了したらイベントリスナーを追加
document.addEventListener('DOMContentLoaded', () => {
  const signInButton = document.getElementById('signInButton');
  signInButton.addEventListener('click', signIn);
});

// Cognitoに対して認証リクエストを送る
async function signIn() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const responseOutput = document.getElementById('responseOutput');

  // CognitoのIdentityServiceProviderクライアントを作成
  const cognito = new AWS.CognitoIdentityServiceProvider();

  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',  // パスワード認証
    ClientId: CLIENT_ID,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password
    }
  };

  try {
    // Cognitoに対してInitiateAuthリクエストを送信
    const authResult = await cognito.initiateAuth(params).promise();
    console.log('Auth Success:', authResult);
    console.log('Auth Success:', authResult.AuthenticationResult);

    const idToken = authResult.AuthenticationResult.IdToken;
    console.log('ID Token:', idToken);

    // 取得したIDトークンを使って Create Session
    // ID Token をバックエンドに POST リクエストで送信
    fetch('/api/session', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        idToken: idToken
      })
    })
      .then(response => {
        if (!response.ok) {
          throw new Error('Failed to create session');
        }
        return response.json();
      })
      .then(data => {
        console.log('Session created:', data['user']);
        window.location.href = '/private'
      })
      .catch(error => {
        console.error('Error creating session:', error);
      });

  } catch (error) {
    console.error('Error during sign in:', error);
    responseOutput.textContent = 'Error: ' + error.message;
  }
}

document.getElementById('googleLogin').addEventListener('click', () => {
  const redirectUri = 'https://<your server>/accounts/amazon-cognito/login/callback/'
  const cognitoDomain = '<cognito user pool name>.ap-northeast-1.amazoncognito.com'
  const clientId = CLIENT_ID

  const authUrl = `https://${cognitoDomain}/oauth2/authorize?identity_provider=Google&response_type=token&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=email+openid+profile`;
  window.location.href = authUrl;
});
const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const path = require('path');

const PORT = 8080;

// Cognito User Pool の設定
const COGNITO_JWKS_URI = 'https://cognito-idp.ap-northeast-1.amazonaws.com/<user pool id>/.well-known/jwks.json';  // Cognito の公開鍵 URL
const COGNITO_ISSUER = `https://cognito-idp.ap-northeast-1.amazonaws.com/<user pool id>`;  // Cognito の Issuer URL

// Express アプリの作成
const app = express();
app.use(express.json()); // JSON リクエストをパース

// 静的ファイルを提供する (index.html と JavaScript)
app.use(express.static(path.join(__dirname, '/')));

// セッション設定
app.use(session({
  secret: 'your-secret-key',  // ここは強力な秘密鍵に置き換えてください
  resave: false,
  saveUninitialized: false,
  //cookie: { secure: false, httpOnly: true, sameSite: 'None' }  // https でない場合は false
}));

// JWKS クライアントの設定
const jwksClient = jwksRsa({
  jwksUri: COGNITO_JWKS_URI
});

// Cognito の公開鍵を取得し、トークンを検証
function getKey(header, callback) {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
    } else {
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    }
  });
}

// ID Token を検証してセッションを作成するルート
app.post('/api/session', (req, res) => {
  const idToken = req.body.idToken;

  if (!idToken) {
    return res.status(400).send('ID Token is required');
  }

  // ID Token の検証
  jwt.verify(idToken, getKey, {
    audience: '<client id>',  // Cognito User Pool クライアント ID
    issuer: COGNITO_ISSUER,
    algorithms: ['RS256']
  }, (err, decoded) => {
    if (err) {
      return res.status(401).send('Invalid ID Token');
    }

    // 検証が成功した場合、セッションを作成し, Redirect
    req.session.user = {
      sub: decoded.sub,  // Cognito ユーザーのサブジェクト (ユーザーID)
      email: decoded.email,
      username: decoded['cognito:username']
    };
    //console.log('session: ', req.session)

    res.json({ message: 'Session created', user: req.session.user });
  });
});

app.get('/private', (req, res) => {
  if (!req.session.user) {
    console.log('private: Unauthorized request')
    return res.redirect('/');
  }
  console.log('private: Authorized request [user]', req.session.user.email)
  res.send(`<h1>Secret Page</h1><p>Welcome, ${req.session.user.email}!</p><form method="POST" action="/logout"><button type="submit">Logout</button></form>`);
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Failed to logout');
    }
    res.redirect('/');
  });
});

app.get('/accounts/amazon-cognito/login/callback', async (req, res) => {
  const idToken = req.body.idToken;

  // ここのページのJSで/api/sessionへID Token送信
  res.sendFile(path.join(__dirname, 'callback.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
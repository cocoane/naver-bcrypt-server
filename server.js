const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // bcryptjs 사용
const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(express.json());
app.use(cors());

// 헬스 체크
app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Naver SmartStore Signature Server is running',
    current_timestamp_ms: Date.now(),
    timestamp: new Date().toISOString()
  });
});

// 밀리초 timestamp 생성
app.get('/timestamp', (req, res) => {
  const now = Date.now();
  res.json({
    timestamp_ms: now,
    timestamp_readable: new Date(now).toISOString(),
    note: 'Use timestamp_ms for Naver signature generation'
  });
});

// 디버깅용
app.post('/debug', (req, res) => {
  res.json({
    received_body: req.body,
    received_headers: req.headers,
    body_type: typeof req.body,
    keys_received: Object.keys(req.body || {}),
    timestamp: new Date().toISOString()
  });
});

// 전자서명 생성 (Python bcrypt + Base64 방식과 동일)
app.post('/naver-signature', async (req, res) => {
  try {
    const { client_id, timestamp, client_secret } = req.body;
    
    if (!client_id || !timestamp || !client_secret) {
      return res.status(400).json({ 
        error: 'Missing required parameters',
        required: ['client_id', 'timestamp', 'client_secret']
      });
    }

    // password = client_id + "_" + timestamp
    const password = `${client_id}_${timestamp}`;

    // bcrypt hash 생성 (salt = client_secret)
    const hashed = bcrypt.hashSync(password, client_secret);

    // Base64 인코딩
    const signature = Buffer.from(hashed).toString('base64');

    // 전자서명 반환 (문자열 그대로)
    res.send(signature);

  } catch (error) {
    console.error('Signature generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate signature',
      message: error.message
    });
  }
});

// 404 핸들링
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    available_endpoints: [
      'GET /',
      'GET /timestamp',
      'POST /debug',
      'POST /naver-signature'
    ]
  });
});

// 서버 실행
app.listen(PORT, () => {
  console.log(`Naver SmartStore Signature Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/`);
  console.log(`Signature endpoint: POST http://localhost:${PORT}/naver-signature`);
});

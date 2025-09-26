const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(express.json());
app.use(cors());

// 헬스 체크 엔드포인트
app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Naver SmartStore BCrypt Server is running',
    current_timestamp_ms: Date.now(),
    timestamp: new Date().toISOString()
  });
});

// 현재 밀리초 타임스탬프 생성 엔드포인트
app.get('/timestamp', (req, res) => {
  const now = Date.now();
  res.json({
    timestamp_ms: now,
    timestamp_readable: new Date(now).toISOString(),
    note: 'Use timestamp_ms value for Naver signature generation'
  });
});

// 디버깅용 - 받은 요청 내용 확인
app.post('/debug', (req, res) => {
  console.log('Received request body:', req.body);
  console.log('Request headers:', req.headers);
  
  res.json({
    received_body: req.body,
    received_headers: req.headers,
    body_type: typeof req.body,
    keys_received: Object.keys(req.body || {}),
    timestamp: new Date().toISOString()
  });
});

// 네이버 스마트스토어 전자서명 생성 엔드포인트
app.post('/naver-signature', async (req, res) => {
  try {
    const { client_id, timestamp, client_secret } = req.body;
    
    // 필수 파라미터 검증
    if (!client_id || !timestamp || !client_secret) {
      return res.status(400).json({ 
        error: 'Missing required parameters',
        required: ['client_id', 'timestamp', 'client_secret'],
        received: {
          client_id: !!client_id,
          timestamp: !!timestamp,
          client_secret: !!client_secret
        },
        note: 'timestamp should be milliseconds since Unix epoch'
      });
    }

    // 타임스탬프 형식 검증 (밀리초 단위 Unix 시간)
    const timestampStr = timestamp.toString();
    const timestampNum = parseInt(timestamp);
    if (isNaN(timestampNum)) {
      return res.status(400).json({
        error: 'Invalid timestamp format',
        required: 'Numeric timestamp in milliseconds',
        received: timestamp,
        example: Date.now().toString()
      });
    }

    // 네이버 스마트스토어 전자서명 생성 규칙
    // password = client_id + "_" + timestamp (밀리초)
    const password = `${client_id}_${timestampStr}`;
    
    console.log('Generating signature with password:', password);
    console.log('Client secret length:', client_secret.length);

    // BCrypt salt 생성 (client_secret를 기반으로 적절한 salt 생성)
    // 네이버 API 문서에 따르면 client_secret을 salt로 사용한다고 했지만,
    // BCrypt의 경우 salt 형식이 특별해야 함
    
    // 방법 1: client_secret을 이용해 bcrypt salt 생성
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    
    // client_secret을 패스워드에 포함시키는 방식으로 변경
    const passwordWithSecret = `${password}_${client_secret}`;
    
    // BCrypt 해시 생성
    const signature = await bcrypt.hash(passwordWithSecret, salt);
    
    res.json({ 
      signature: signature,
      client_id: client_id,
      timestamp: timestampStr,
      timestamp_ms: timestampNum,
      timestamp_readable: new Date(timestampNum).toISOString(),
      password_used: password,
      generated_at: new Date().toISOString(),
      method: 'bcrypt_with_generated_salt'
    });

  } catch (error) {
    console.error('Signature generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate signature',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// 전자서명 검증 엔드포인트 (테스트용)
app.post('/verify-signature', async (req, res) => {
  try {
    const { client_id, timestamp, client_secret, signature } = req.body;
    
    if (!client_id || !timestamp || !client_secret || !signature) {
      return res.status(400).json({ 
        error: 'Missing required parameters for verification'
      });
    }

    const password = `${client_id}_${timestamp}`;
    const isValid = await bcrypt.compare(password, signature);
    
    res.json({ 
      valid: isValid,
      password_used: password,
      verified_at: new Date().toISOString()
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ 
      error: 'Failed to verify signature' 
    });
  }
});

// 에러 핸들링
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error' 
  });
});

// 404 핸들러
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    available_endpoints: [
      'GET /',
      'GET /timestamp',
      'POST /debug',
      'POST /naver-signature',
      'POST /verify-signature'
    ]
  });
});

app.listen(PORT, () => {
  console.log(`Naver SmartStore BCrypt Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/`);
  console.log(`Signature endpoint: POST http://localhost:${PORT}/naver-signature`);
});
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
        required: ['client_id', 'timestamp', 'client_secret']
      });
    }

    // 네이버 스마트스토어 전자서명 생성 규칙
    // password = client_id + "_" + timestamp
    const password = `${client_id}_${timestamp}`;
    
    // salt = client_secret
    const salt = client_secret;

    console.log('Generating signature with:', {
      password: password,
      salt: salt.substring(0, 10) + '...' // 보안을 위해 일부만 로그
    });

    // BCrypt.hashpw(password, salt) 실행
    const signature = await bcrypt.hash(password, salt);
    
    res.json({ 
      signature: signature,
      client_id: client_id,
      timestamp: timestamp,
      generated_at: new Date().toISOString()
    });

  } catch (error) {
    console.error('Signature generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate signature',
      message: error.message 
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
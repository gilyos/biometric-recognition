const https = require('https');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());
const URL = '5fb3-2a0d-6fc2-4b10-800-6812-47b2-bfeb-a736.ngrok-free.app'

// Allow CORS for your local network
app.use(cors({
  //origin: [`https://${URL}`],
  origin: [`*`],
  methods: ['GET', 'POST'],
}));

// Serve static files (like index.html and script.js)
app.use(express.static('../client'));

// In-memory storage for simplicity (use a database in production)
const users = {};

app.get('biometric-recognition/api/generate-registration-options', async (req, res) => {
  let userId = req.query.userId || uuidv4();
  let userName = req.query.userName || '';
  const challenge = crypto.randomBytes(32).toString('base64url'); // Generate a 32-byte random challenge
  const user = users[userId] || { id: userId, credentials: [] };
  
  const options =  await generateRegistrationOptions({
    rpName: 'Skillonnet',
    //rpID: '4b6e-2a0d-6fc2-4b10-800-6812-47b2-bfeb-a736.ngrok-free.app', // Replace with your IP or hostname
    userID: Buffer.from(user.id, 'utf-8'),
    userName: userName, // Replace with actual user name
    attestationType: 'direct',
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // Use platform authenticator
      requireResidentKey: true,
    },
    userVerification: 'required',
    challenge,
    supportedAlgorithmIDs: [-7, -257], // Example algorithms (RS256, ES256)
  });

  users[userId] = user;
 
  //users[userId].currentRegistrationChallenge = challenge;
  users[userId].currentRegistrationChallenge = Buffer.from(challenge, 'utf-8').toString('base64url');
  options.user.id = Buffer.from(user.id, 'utf-8').toString('base64url');
  console.log(`>>>> userId base64: ${user.id}`);
  res.json(options);
});

app.post('biometric-recognition/api/verify-registration', async (req, res) => {

  const { userId, attestationResponse } = req.body;
  const decodedUserId = Buffer.from(userId, 'base64url').toString('utf-8');
  const user = users[decodedUserId];

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  try {
    attestationResponse.id = Buffer.from(attestationResponse.id, 'base64url').toString('base64');
    const verificationResult = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: user.currentRegistrationChallenge,
      //expectedOrigin: `https://${URL}`,
      //expectedRPID: '4b6e-2a0d-6fc2-4b10-800-6812-47b2-bfeb-a736.ngrok-free.app',
    });

    if (verificationResult.verified) {
      user.credentials.push(verificationResult.registrationInfo.credential.id);
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Verification failed' });
  }
});


// Start HTTPS server
const PORT = 3232;
https.createServer(app).listen(PORT, () => {
  console.log(`HTTP Server running at http://${URL}`);
});
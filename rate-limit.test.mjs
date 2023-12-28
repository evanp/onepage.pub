import { describe, beforeEach, afterEach, it } from 'node:test'
import assert from 'node:assert'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import 'dotenv/config'

const MAIN_PORT = process.env.OPP_PORT
console.log(`\nRate Limit: ${process.env.OPP_RATE_LIMIT}\n`)
/*
const server = https.createServer((req, res) => {
  try {
    // server logic here
  } catch (err) {
    console.error(err);
    res.statusCode = 500;
    res.end('Internal Server Error'); 
  }
});

server.listen(MAIN_PORT, () => {
  console.log(`Server listening on port: ${MAIN_PORT}`);
});

server.on('error', (err) => {
  console.error('Server error:', err);
});
*/

describe('request rate limits', () => {

    const options = {
        hostname: 'localhost',
        port: MAIN_PORT,
        path: '/',
        method: 'GET'  
    };
  
  beforeEach( () => {
    console.log(`starting rate limit tests\n`)

    const options = {
      key: readFileSync(process.env.OPP_KEY),
      cert: readFileSync(process.env.OPP_CERT)
    };
    
    try {
      https.createServer(options, (req, res) => {
        try {
          res.writeHead(200);
          res.end('hello world\n hello');
        } catch (err) {
          console.error(err);
          res.statusCode = 500;
          res.end('Internal Server Error'); 
        }
      }).listen(process.env.OPP_PORT);
    } catch (err) {
      console.error('Error starting HTTPS server:', err);
      process.exit(1);
    }
    console.log(`Server listening on port: ${process.env.OPP_PORT}`);
  })

  afterEach(() => {
    https.close
    console.log(`finished rate limit tests\n`)
  })

    it('should limit requests per IP', async () => {
      let nextCallCount = 0;
       
      // Call limiter middleware multiple times from same IP
      for(let i = 0; i < 150; i++) {
        
        const req = https.request(options, (res) => {

          if (res.statusCode === 200) {
              // success
              nextCallCount++;
            } else {
              // handle error
            }
                     
        });
          req.on('error', (e) => {
            console.error(`problem with request: ${e.message}`);
          });
                    
          req.end();
      }
      return nextCallCount;
      
      // Assert request was blocked after exceeding limit
      assert.strictEqual(nextCallCount, 100);
    });
      
    it('should allow requests below limit', async () => {
      let nextCallCount = 0;
        
      // Call limiter middleware below limit
      for(let i = 0; i < 50; i++) {
        const req = https.request(options, (res) => {

          if (res.statusCode === 200) {
              // success
              nextCallCount++;
            } else {
              // handle error
            }
                     
        });
          req.on('error', (e) => {
            console.error(`problem with request: ${e.message}`);
          });
                    
          req.end();
      }
      return nextCallCount;
  
      // Assert next() was called for all requests 
      assert.strictEqual(nextCallCount, 50);
    });
  
  });

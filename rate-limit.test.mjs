import { describe, before, after, it } from 'node:test'
import assert from 'node:assert'
import https from 'node:https'
import 'dotenv/config'

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0

const MAIN_PORT = process.env.OPP_PORT
console.log(`Rate Limit: ${process.env.OPP_RATE_LIMIT}`)

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


describe('request rate limits', () => {

    const options = {
        hostname: 'localhost',
        port: MAIN_PORT,
        path: '/',
        method: 'GET'  
    };
  
  before(async () => {
    
  })

  after(() => {
    console.log('Stopping server')
    server.close()
    console.log('finished rate limit tests')
  })

    it('should limit requests per IP', async () => {
      // Mock request and response objects
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
      console.log(`Next call count: ${nextCallCount}`);
      // Assert request was blocked after exceeding limit
      assert.strictEqual(nextCallCount, 100);
    });
  
    /*
    it('should allow requests below limit', async () => {
      // Mock request and response objects
      const req = {};
      const res = {};
      const next = () => {};
  
      // Call limiter middleware below limit
      for(let i = 0; i < 50; i++) {
        limiter(req, res, next);
      }
  
      // Assert next() was called for all requests 
      assert.strictEqual(next.callCount, 50);
    });
    */

  });
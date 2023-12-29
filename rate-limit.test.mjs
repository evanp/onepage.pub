import { describe, beforeEach, afterEach, it } from 'node:test'
import assert from 'node:assert'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import 'dotenv/config'

const MAIN_PORT = process.env.OPP_PORT
console.log(`\nRate Limit: ${process.env.OPP_RATE_LIMIT}\n\nstarting rate limit tests\n`)

describe('request rate limits', () => {

    const options = {
        hostname: 'localhost',
        port: MAIN_PORT,
        path: '/',
        method: 'GET'  
    };
  
  beforeEach( () => {
    
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
  })

  afterEach(() => {
    https.close
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
            if (e.message != 'self-signed certificate') {
              console.error(`problem with request: ${e.message}`);
            }
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
            if (e.message != 'self-signed certificate') {
              console.error(`problem with request: ${e.message}`);
            }
          });
           
          req.end();
      }
      return nextCallCount;
  
      // Assert all 50 requests were processed 
      assert.strictEqual(nextCallCount, 50);
    });
    
    it('uses standard headers', async () => {

      const req = https.request(options, (res) => {

        if (res.statusCode === 200) {
            // success
            assert(res.headers['RateLimit-Limit']);
            assert(res.headers['RateLimit-Remaining']); 
            assert(res.headers['RateLimit-Reset']);
    
            assert(!res.headers['X-RateLimit-Limit']);
            assert(!res.headers['X-RateLimit-Remaining']);
            assert(!res.headers['X-RateLimit-Reset']);
          }
               
      });
        req.on('error', (e) => {
          if (e.message != 'self-signed certificate') {
            console.error(`problem with request: ${e.message}`);
          }
        });
         
        req.end();
    });
  
  });
  
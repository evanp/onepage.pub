import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import 'dotenv/config'

const options = {
  key: readFileSync(process.env.OPP_KEY),
  cert: readFileSync(process.env.OPP_CERT)
};

try {
  createServer(options, (req, res) => {
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
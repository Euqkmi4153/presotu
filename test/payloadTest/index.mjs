import path from 'path';
import { fileURLToPath } from 'url';
// The two tests marked with concurrent will be run in parallel
import fs from 'fs';
const __filename = fileURLToPath(import.meta.url);
const sliceLocation = __filename.lastIndexOf('.spec');

const __dirname = path.dirname(__filename);
const testCase = fs.readFileSync(
  `${__dirname}/${__filename.slice(0, sliceLocation)}-00.txt`,
  'utf-8'
);
console.log(testCase);
console.log(__dirname);
console.log(__filename);

// The two tests marked with concurrent will be run in parallel
const sliceCount = 'payloadTest.spec.js'.lastIndexOf('.spec');
console.log(`${'payloadTest.spec.js'.slice(0, sliceCount)}-00.txt`);

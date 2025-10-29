import { describe, expect, test } from 'vitest';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import { cspExec } from '../cspExec';
// The two tests marked with concurrent will be run in parallel

const testCase = fs.readFileSync(
  `${__dirname}/PayLoadTestFile/payloadTest-04.txt`,
  'utf-8'
);
describe('payLoadTest', () => {
  const ArrayTestCases = testCase.split('\n').filter((v) => v);
  for (const testCase of ArrayTestCases) {
    test(testCase, async () => {
      const result = await cspExec(testCase);
      console.log(result);
      expect(result).toMatchSnapshot();
    });
  }
});

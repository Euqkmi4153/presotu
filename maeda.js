import * as espree from 'espree';
import fs from 'fs';
const path = fs.readFileSync('./sample/inlineScript.html', 'utf-8');

const index = (path) => {
    const ast = espree.parse(path);
    console.log(ast);
};

index(path);
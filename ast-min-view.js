// ast-min-view.js (CommonJS版)
const espree = require('espree');
const estraverse = require('estraverse');

const code = `const x = 1 + 2 * y;`;

const ast = espree.parse(code, { ecmaVersion: 'latest', loc: true });

estraverse.traverse(ast, {
    enter(node) {
        if (node.type === 'Identifier') {
            console.log(`Id(${node.name}) @ line ${node.loc.start.line}`);
        }
        if (node.type === 'BinaryExpression') {
            console.log(`Binary(${node.operator})`);
        }
    },
});
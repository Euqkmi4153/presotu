import * as espree from 'espree';
import estraverse from 'estraverse';
import fs from 'fs';
const path = fs.readFileSync('./sample/innerHTML/innerHTML.js', 'utf-8');
console.log(typeof path);
const index = (path) => {
    const ast = espree.parse(path);
    estraverse.traverse(ast, {
        enter: function (node, parent) {
            console.log(node);
        },
        leave: function (node, parent) {
            if (node.type == 'VariableDeclarator') console.log(node.id.name);
        },
    });
    // console.log(
    //   ast.body.map((node) => {
    //     return node.declarations;
    //   })
    // );
};

index(path);
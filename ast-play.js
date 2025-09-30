// ast-play.js
// 1) 解析 → 2) 走査 → 3) 変換 → 4) 再生成 を一気に体験

import * as espree from 'espree';
import estraverse from 'estraverse';
import escodegen from 'escodegen';

// 解析対象コード
const code = `
  // サンプル: x を使った式と関数
  const x = 1 + 2 * y;
  function f(a) { return a + x; }
  console.log(f(10));
`;

// ===== 1) パース（AST生成） =====
const ast = espree.parse(code, {
    ecmaVersion: 'latest',
    sourceType: 'module',
    loc: true,   // 行・列
    range: true, // 文字位置
    comment: true,
    tokens: true
});

console.log('=== 生成されたASTのトップ ===');
console.log(ast.type, 'body.length =', ast.body.length);

// ===== 2) 走査（読み取り） =====
// すべてのノードを前順で訪問して、要点を表示
console.log('\n=== ノード訪問ログ ===');
estraverse.traverse(ast, {
    enter(node, parent) {
        if (node.type === 'Identifier') {
            console.log(`Identifier: ${node.name} @ line ${node.loc.start.line}`);
        }
        if (node.type === 'BinaryExpression') {
            console.log(
                `BinaryExpression: ${node.left.type} ${node.operator} ${node.right.type}`
            );
        }
        if (node.type === 'CallExpression' && node.callee?.object?.name === 'console') {
            console.log('Found console.* call');
        }
    }
});

// ===== 3) 変換（ASTを書き換える） =====
// 例A: すべての Identifier "x" を "x1" にリネーム
estraverse.replace(ast, {
    enter(node) {
        if (node.type === 'Identifier' && node.name === 'x') {
            return { ...node, name: 'x1' };
        }
    }
});

// 例B: 簡単な定数畳み込み (1 + 2 などを 3 に置換)
// BinaryExpression の左右が数値リテラルなら計算して Literal に置換
estraverse.replace(ast, {
    leave(node) {
        if (
            node.type === 'BinaryExpression' &&
            node.left.type === 'Literal' &&
            node.right.type === 'Literal'
        ) {
            const { operator } = node;
            const a = node.left.value;
            const b = node.right.value;
            try {
                // 安全のため演算子を限定
                if (['+', '-', '*', '/', '%', '**', '<<', '>>', '&', '|', '^'].includes(operator)) {
                    // eslint-disable-next-line no-eval
                    const value = eval(`${a} ${operator} ${b}`);
                    return { type: 'Literal', value, raw: String(value) };
                }
            } catch (_) { }
        }
    }
});

// ===== 4) コード再生成 =====
const out = escodegen.generate(ast, { format: { indent: { style: '  ' } } });
console.log('\n=== 変換後コード ===\n' + out);

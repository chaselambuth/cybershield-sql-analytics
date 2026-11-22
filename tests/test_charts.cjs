const {test} = require('node:test');
const assert = require('node:assert/strict');
const charts = require('../src/cybershield/web_assets/static/charts.js');

test('missing, boolean and unsafe values never become zero bars', () => {
  for (const value of [null, true, false, '', ' ', 'NaN', 'Infinity', [], {}, '9007199254740993']) {
    assert.equal(charts.numeric(value), null);
  }
  assert.equal(charts.numeric('0'), 0);
  assert.equal(charts.numeric('-3.25'), -3.25);
});

test('only finite numeric columns are offered as values', () => {
  assert.deepEqual(charts.numericColumns({columns: ['name','count','flag'], rows: [['A','2',true],['B',null,false]]}), [1]);
});

test('charts preserve query order and disclose omitted or capped rows', () => {
  const result = {columns: ['source','flows'], rows: Array.from({length: 35}, (_, i) => ['host-'+i, i])};
  result.rows.push(['missing',null]);
  const data = charts.series(result, 0, 1, 'bar');
  assert.equal(data.points.length, 30);
  assert.equal(data.points[0].value, 0);
  assert.equal(data.points[29].label, 'host-29');
  assert.equal(data.hidden, 5);
  assert.equal(data.omitted, 1);
  assert.equal(data.total, 36);
  assert.equal(charts.series(result, 0, 1, 'line').points.length, 35);
});

test('negative values and repeated categories remain separate returned rows', () => {
  const data = charts.series({columns:['category','delta'],rows:[['A',-2],['A',3],['B',0]]},0,1,'bar');
  assert.deepEqual(data.points,[{label:'A',value:-2},{label:'A',value:3},{label:'B',value:0}]);
});

function renderedLine(rows) {
  class Node {
    constructor(tag) { this.tag = tag; this.attrs = {}; this.children = []; }
    setAttribute(key, value) { this.attrs[key] = value; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
  }
  const previous = global.document;
  global.document = {createElementNS: (_, tag) => new Node(tag)};
  try {
    const container = new Node('div');
    const data = charts.render(container, {columns:['hour','flows'], rows}, {x:0, y:1, type:'line', title:'Traffic'});
    return {data, nodes:container.children[0].children};
  } finally { global.document = previous; }
}

test('line charts keep missing row positions and never join across a gap', () => {
  for (const missing of [null, true, 'NaN', '9007199254740993']) {
    const {data, nodes} = renderedLine([['09:00',10],['10:00',missing],['11:00',20],['12:00',30]]);
    const dots = nodes.filter(n => n.tag === 'circle').map(n => Number(n.attrs.cx));
    const lines = nodes.filter(n => n.tag === 'polyline');
    assert.equal(data.omitted, 1);
    assert.equal(lines.length, 1);
    assert.equal(lines[0].attrs.points.split(' ').length, 2);
    assert.equal(Number(lines[0].attrs.points.split(',')[0]), dots[1]);
    assert.ok(Math.abs((dots[1] - dots[0]) / (dots[2] - dots[1]) - 2) < 1e-10);
  }
});

test('leading and trailing missing rows retain space and isolated points stay unconnected', () => {
  const {data, nodes} = renderedLine([['08:00',null],['09:00',10],['10:00',null],['11:00',20],['12:00',null]]);
  assert.equal(data.slots, 5);
  assert.equal(nodes.filter(n => n.tag === 'circle').length, 2);
  assert.equal(nodes.filter(n => n.tag === 'polyline').length, 0);
  const dots = nodes.filter(n => n.tag === 'circle').map(n => Number(n.attrs.cx));
  const grid = nodes.find(n => n.tag === 'line');
  assert.ok(dots[0] > Number(grid.attrs.x1));
  assert.ok(dots[1] < Number(grid.attrs.x2));
});

test('line display cap retains gaps before the last plotted point', () => {
  const rows = Array.from({length:105}, (_, i) => [String(i), i === 2 ? null : i]);
  const data = charts.series({columns:['x','y'], rows}, 0, 1, 'line');
  assert.equal(data.points.length, 100);
  assert.equal(data.hidden, 4);
  assert.equal(data.omitted, 1);
  assert.equal(data.slots, 101);
  assert.equal(data.points.at(-1).index, 100);
});

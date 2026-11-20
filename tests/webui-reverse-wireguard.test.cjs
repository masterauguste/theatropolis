const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../internal/webui/assets/app.js'), 'utf8');

function harness(destinationName = 'child_agent') {
  class Input {
    constructor(value = '') { this.value = value; this.dataset = {}; this.validity = {valid: true}; this.previousElementSibling = {}; }
    setCustomValidity(message) { this.validity.valid = !message; }
    closest() { return null; }
  }
  class Select extends Input {
    constructor(value = '') { super(value); this.options = []; this.events = []; }
    get selectedOptions() { return this.options.filter(option => option.value === this.value); }
    replaceChildren(...options) { this.options = options; }
    add(option) { this.options.push(option); }
    dispatchEvent(event) { this.events.push(event.type); }
  }
  class Option {
    constructor(text, value) { this.text = text; this.value = value; this.dataset = {}; }
  }
  const fields = { protocol: new Select('anytls'), listen: new Input('::'), listen_port: new Input('443') };
  fields.protocol.options = ['shadowsocks', 'anytls', 'hysteria2', 'reverse_wireguard'].map(value => new Option(value, value));
  const destination = new Select('child');
  destination.options = [Object.assign(new Option('NAT child', 'child'), {dataset: {reverseOnly: '1'}}), new Option('Public', 'public')];
  const picker = new Select('manual');
  const form = {querySelector(selector) {
    if (selector === `[name="${destinationName}"]` || selector === '[name="child_agent"], [name="agent_id"]') return destination;
    return selector === '[name="protocol"]' ? fields.protocol : null;
  }};
  const editor = {dataset: {agent: 'child', parentAgent: 'parent', allowReverse: '1'}, closest() {return form;},
    querySelector(selector) { if (selector === '[data-proxy-listener-select]') return picker; return fields[selector.match(/^\[name="(.+)"\]$/)?.[1]] || null; },
    querySelectorAll() { return []; },
  };
  const catalog = [
    {agent: 'parent', protocol: 'reverse_wireguard', listen: '::', port: 51820, listenerId: 'parent-wg', selectable: true},
    {agent: 'child', protocol: 'reverse_wireguard', listen: '::', port: 51821, listenerId: 'wrong-owner', selectable: true},
    {agent: 'public', protocol: 'anytls', listen: '::', port: 443, listenerId: 'public-tls', selectable: true},
  ];
  const context = vm.createContext({editor, catalog, window: {}, document: {}, HTMLInputElement: Input, HTMLSelectElement: Select, Option,
    Event: class {constructor(type) {this.type = type;}}, t: message => message, updateOwnedControlValidity: control => control.setCustomValidity(control.dataset.listenerConflict || ''),
    updateProxyEndpointForm() {},
  });
  vm.runInContext('const proxyListenerCatalog = catalog;', context);
  vm.runInContext(source.slice(source.indexOf('const proxyListenerAgent ='), source.indexOf('for (const editor of document.querySelectorAll("[data-proxy-listener-editor]")')), context);
  return {editor, form, fields, destination, picker, catalog, run: code => vm.runInContext(code, context)};
}

for (const name of ['child_agent', 'agent_id']) {
  test(`CGNAT ${name} selection forces reverse transport and uses parent listener presets`, () => {
    const h = harness(name);
    h.run('updateProxyListenerChoices(editor)');
    assert.equal(h.fields.protocol.value, 'reverse_wireguard');
    assert.ok(h.fields.protocol.options.filter(option => option.value !== 'reverse_wireguard').every(option => option.disabled));
    assert.equal(h.fields.listen_port.value, '51820');
    assert.equal(h.fields.listen_port.min, '1024');
    assert.equal(h.fields.listen_port.previousElementSibling.textContent, 'Parent WireGuard UDP port');
    assert.equal(h.fields.listen.readOnly, true);
    assert.deepEqual(h.picker.options.map(option => option.value), ['manual', 'parent-wg']);
    assert.equal(h.run('proxyListenerAgent(editor)'), 'parent');
    assert.ok(h.fields.protocol.events.includes('change'));
    h.destination.value = 'public';
    h.run('updateProxyListenerChoices(editor)');
    assert.equal(h.fields.protocol.value, 'anytls');
    assert.equal(h.fields.listen.readOnly, false);
    assert.equal(h.fields.listen_port.min, '1');
    assert.deepEqual(h.picker.options.map(option => option.value), ['manual', 'public-tls']);
  });
}

test('reverse listener editing keeps parent ownership without a destination selector', () => {
  const h = harness();
  h.form.querySelector = selector => selector === '[name="protocol"]' ? h.fields.protocol : null;
  h.fields.protocol.value = 'reverse_wireguard';
  h.editor.dataset.currentListener = 'parent-wg';
  h.picker.value = '';
  h.run('updateProxyListenerChoices(editor)');
  assert.equal(h.run('proxyListenerAgent(editor)'), 'parent');
  assert.equal(h.picker.value, 'parent-wg');
});

test('parent WireGuard wildcard socket conflicts with another UDP listener, but not TCP', () => {
  const h = harness();
  h.run('updateProxyListenerChoices(editor)');
  h.catalog.splice(0, h.catalog.length, {agent: 'parent', protocol: 'hysteria2', listen: '203.0.113.1', port: 51820, listenerId: 'occupied', label: 'UDP'});
  h.run('validateProxyListener(editor)');
  assert.ok(h.fields.listen_port.dataset.listenerConflict);
  h.catalog[0].protocol = 'anytls';
  h.run('validateProxyListener(editor)');
  assert.equal(h.fields.listen_port.dataset.listenerConflict, undefined);
});

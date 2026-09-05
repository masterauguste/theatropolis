const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../internal/webui/assets/app.js'), 'utf8');

function harness(fetch) {
  const listeners = {}, windowListeners = {}, navigations = [];
  class Element {
    constructor(tag = '') { this.tag = tag; this.dataset = {}; this.children = []; this.style = {}; this.isConnected = true; }
    append(...children) { this.children.push(...children); }
    prepend(child) { this.children.unshift(child); }
    setAttribute() {}
    removeAttribute() {}
    focus() { this.focused = true; }
    querySelector(selector) { return this.children.find(c => selector === '[data-form-result]' ? c.dataset.formResult !== undefined : c.tag === selector) || null; }
  }
  class Form extends Element {
    constructor() { super('form'); this.method = 'post'; this.action = 'http://localhost/users'; this.elements = []; this.enctype = ''; }
    querySelectorAll() { return []; }
    hasAttribute() { return false; }
  }
  const main = new Element('main');
  const document = {
    modal: false,
    addEventListener(type, fn) { listeners[type] = fn; },
    createElement(tag) { return new Element(tag); },
    querySelectorAll() { return []; },
    querySelector(selector) {
      if (selector === 'main') return main;
      if (selector === 'dialog[open]') return this.modal ? {} : null;
      if (selector === '[data-refresh-notice]') return main.children.find(c => c.dataset.refreshNotice !== undefined) || null;
      return null;
    }, body: main,
  };
  const window = { location: {href:'http://localhost/users', origin:'http://localhost', replace(url){navigations.push(url)},assign(url){navigations.push(url)}}, addEventListener(type,fn){windowListeners[type]=fn}, setTimeout(){} };
  const context = vm.createContext({window,document,URL,URLSearchParams,TypeError,HTMLFormElement:Form,HTMLButtonElement:Element,
    FormData: class { set(){} *[Symbol.iterator](){yield ['name','draft'];} },
    DOMParser: class { parseFromString(text){return {querySelector(){return {textContent:text}}}} },
    fetch:(...args)=>fetch(...args).then(value=>({headers:new Map(),...value}))});
  vm.runInContext(source.slice(0, source.indexOf('const localDateTimeFormatter')),context);
  const sessionStart=source.indexOf('const redirectForExpiredSession =');
  vm.runInContext(source.slice(sessionStart,source.indexOf('\n};',sessionStart)+3),context);
  vm.runInContext(source.slice(source.indexOf('// Existing specialized submit handlers')),context);
  return {context,document,listeners,windowListeners,navigations,main,Form,
    run(code){return vm.runInContext(code,context)},
    submit(form){return listeners.submit({target:form,defaultPrevented:false,preventDefault(){this.defaultPrevented=true}})},
  };
}

test('a deployment completing after typing never reloads or loses the draft',()=>{
  const h=harness();const form=new h.Form();
  h.listeners.input({target:{form}});
  h.run('refreshWithoutLosingDrafts()');h.run('refreshWithoutLosingDrafts()');
  assert.equal(h.navigations.length,0);assert.equal(h.main.children.length,1);
  let prevented=false;h.windowListeners.beforeunload({preventDefault(){prevented=true}});assert.equal(prevented,true);
  h.listeners.reset({target:form});h.run('refreshWithoutLosingDrafts()');assert.equal(h.navigations.length,1);
});

test('an open clean editor also defers automatic refresh',()=>{
  const h=harness();h.document.modal=true;h.run('refreshWithoutLosingDrafts()');
  assert.equal(h.navigations.length,0);assert.equal(h.main.children.length,1);
});

test('session expiry preserves the draft and offers sign-in in another tab',()=>{
  const h=harness();const form=new h.Form();h.listeners.change({target:{form}});
  assert.equal(h.run('redirectForExpiredSession({status:401})'),true);
  assert.equal(h.navigations.length,0);
  const link=h.main.children[0].querySelector('a');assert.equal(link.href,'/login');assert.equal(link.target,'_blank');
});

test('ordinary form errors remain on the form and release the submit lock',async()=>{
  const h=harness(async()=>({status:409,ok:false,headers:new Map([['Content-Type','text/plain']]),text:async()=> 'Choose a different name.'}));
  const form=new h.Form();h.listeners.input({target:{form}});await h.submit(form);
  assert.equal(h.navigations.length,0);assert.equal(form.dataset.submitting,undefined);
  assert.equal(form.querySelector('[data-form-result]').textContent,'Choose a different name.');
  assert.equal(h.run('hasUnsavedChanges()'),true);
});

test('two submissions in flight produce only one write',async()=>{
  let release,calls=0;
  const h=harness(()=>{calls++;return new Promise(resolve=>{release=resolve})});const form=new h.Form();
  const first=h.submit(form);await h.submit(form);assert.equal(calls,1);
  release({status:200,ok:true,url:'http://localhost/users/saved'});await first;
  assert.equal(h.navigations.length,1);assert.equal(form.dataset.submitting,undefined);
});

test('saving one form does not discard another form draft',async()=>{
  const h=harness(async()=>({status:200,ok:true,url:'http://localhost/users/saved'}));
  const first=new h.Form(),second=new h.Form();h.listeners.input({target:{form:first}});h.listeners.input({target:{form:second}});
  await h.submit(first);assert.equal(h.navigations.length,0);assert.equal(h.run('hasUnsavedChanges()'),true);
  assert.match(first.querySelector('[data-form-result]').textContent,/Changes saved/);
});

test('network errors never silently replay a mutation',async()=>{
  let calls=0;const h=harness(async()=>{calls++;throw new TypeError('offline')});const form=new h.Form();await h.submit(form);
  assert.equal(calls,1);assert.equal(h.navigations.length,0);assert.match(form.querySelector('[data-form-result]').textContent,/may have reached the Master/);
});

test('rendered migration results stay visible and never GET the POST-only endpoint',async()=>{
  let calls=0;
  const h=harness(async()=>{calls++;return {status:202,ok:true,redirected:false,url:'http://localhost/settings/migration/restore',
    headers:new Map([['Content-Type','text/html'],['Content-Location','/settings']]),text:async()=> 'Restarting Master. 3 Servers validated.'}});
  const form=new h.Form();await h.submit(form);await h.submit(form);
  assert.equal(calls,1);assert.equal(h.navigations.length,0);
  assert.match(form.querySelector('[data-form-result]').textContent,/3 Servers validated/);
  assert.equal(h.main.children[0].querySelector('a').href,'/settings');
});

test('retry after sign-in refreshes CSRF without reloading or replaying the original write',async()=>{
  const calls=[];
  const h=harness(async(url)=>{calls.push(String(url));return String(url)==='/session/csrf'
    ? {status:200,ok:true,json:async()=>({csrf_token:'new-session-token'})}
    : {status:200,ok:true,redirected:true,url:'http://localhost/users/saved'};});
  const form=new h.Form();h.listeners.input({target:{form}});
  h.run('redirectForExpiredSession({status:401})');assert.equal(calls.length,0);
  await h.submit(form);
  assert.deepEqual(calls,['/session/csrf','http://localhost/users']);assert.equal(h.navigations.length,1);
});

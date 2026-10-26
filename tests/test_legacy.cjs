// Offline regression for the original Node manager's new CAS replacement name.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const updates = [];
const model = class { constructor(o) { Object.assign(this, o); } };
const FC = class {
  async listCustomDomainsWithOptions() {
    return {body: {customDomains: [
      {protocol: 'HTTPS', certConfig: null},
      {protocol: 'HTTPS', domainName: 'api.example.com', certConfig: {
        certName: 'devs-certbot-generated-old', certificate: 'old-cert'}}]}};
  }
  async invokeFunctionWithOptions() {return {headers: {}, body: '123'};}
  async updateCustomDomainWithOptions(domain, req) { updates.push(req); }
};
const CAS = class {
  async getUserCertificateDetailWithOptions() {
    return {body: {name: 'devs-certbot-generated-new', cert: 'new-cert', key: 'new-key'}};
  }
};
const libraries = {
  '@alicloud/fc20230330': new Proxy({default: FC}, {get: (t,k) => t[k] || model}),
  '@alicloud/cas20200407': new Proxy({default: CAS}, {get: (t,k) => t[k] || model}),
  '@alicloud/openapi-client': {Config: model},
  '@alicloud/tea-util': {RuntimeOptions: model, default: {readAsString: async s=>s}},
  '@alicloud/darabonba-stream': {default: {readFromString: s=>s}},
  lodash: {uniq: a=>[...new Set(a)]},
};
const sandbox = {exports: {}, require: k=>libraries[k], console: {log(){}},
  process: {env: {CUSTOM_DOMAIN_REGIONS: 'cn-shanghai', CERT_GENERATOR_FUNCTION_NAME: 'example'}}};
vm.runInNewContext(fs.readFileSync('src/fc-domain-manager/index.js', 'utf8'), sandbox);
(async () => {
  await sandbox.exports.handler({}, {region: 'cn-shanghai', accountId: '123', credentials: {}}, ()=>{});
  assert.equal(updates.length, 1);
  assert.equal(updates[0].body.certConfig.certName, 'devs-certbot-generated-new');
  assert.deepEqual(Object.keys(updates[0].body), ['certConfig']);
  console.log('legacy manager regression: passed');
})().catch(e=>{console.error(e);process.exitCode=1;});

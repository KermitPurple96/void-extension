#!/usr/bin/env node
// Void Extension E2E Audit — structure, cross-refs, features, persistence
// Run: node tests/e2e-audit.js
// NOTE: vm.runInThisContext() is used to unit-test extracted pure functions.
"use strict";
const vm = require("vm");
const fs=require("fs"),path=require("path"),{execFileSync}=require("child_process");
const R=path.join(__dirname,"..");
const html=fs.readFileSync(path.join(R,"panel.html"),"utf8");
const js=fs.readFileSync(path.join(R,"panel.js"),"utf8");
const css=fs.readFileSync(path.join(R,"panel.css"),"utf8");
const bg=fs.readFileSync(path.join(R,"background.js"),"utf8");
const rules=fs.readFileSync(path.join(R,"sensitive-rules.js"),"utf8");
let P=0,F=0;
function t(n,ok){if(ok)P++;else{F++;console.log("  FAIL: "+n);}}
function S(n){console.log("\n-- "+n+" --");}
function xfn(s){let d=0,e=0;for(let i=0;i<s.length;i++){if(s[i]==="{")d++;if(s[i]==="}"){d--;if(d===0){e=i+1;break;}}}return s.substring(0,e);}

S("1. JS Syntax");
["panel.js","background.js","sensitive-rules.js"].forEach(f=>{try{execFileSync("node",["-c",path.join(R,f)],{stdio:"pipe"});t(f,true);}catch{t(f,false);}});

S("2. HTML Structure");
const dO=(html.match(/<div[\s>]/g)||[]).length,dC=(html.match(/<\/div>/g)||[]).length;
t("Divs "+dO+"="+dC,dO===dC);
const tB=(html.match(/data-tab="/g)||[]).length,tP=(html.match(/class="tab-panel/g)||[]).length;
t("Tabs "+tB+"="+tP,tB===tP);
let dp=0,bd=[];html.split("\n").forEach((l,i)=>{dp+=(l.match(/<div[\s>]/g)||[]).length-(l.match(/<\/div>/g)||[]).length;if(l.includes("tab-panel")&&dp!==2)bd.push(i+1);});
t("Depth ok, final="+dp,bd.length===0&&dp===0);
const ids=(html.match(/id="([^"]+)"/g)||[]).map(m=>m.slice(4,-1));
const ic={};ids.forEach(id=>{ic[id]=(ic[id]||0)+1;});
t("No dup IDs ("+ids.length+")",Object.values(ic).every(v=>v===1));

S("3. JS-HTML Cross-Ref");
const ji=[...new Set((js.match(/getElementById\("([^"]+)"\)/g)||[]).map(m=>m.match(/"([^"]+)"/)[1]))];
const hs=new Set(ids);
const cmpLegacy=new Set(["cmp-status","cmp-ignore-headers","cmp-to-rep","cmp-to-intr","cmp-to-poc","cmp-to-notes","cmp-render","cmp-curl","cmp-fetch","cmp-python","cmp-diff","cmp-swap","cmp-clear","cmp-resizer","cmp-left","cmp-right","cmp-left-title","cmp-right-title","cmp-left-req-pre","cmp-left-resp-pre","cmp-right-req-pre","cmp-right-resp-pre","cmp-left-req-pane","cmp-left-resp-pane","cmp-right-req-pane","cmp-right-resp-pane"]);
const mi=ji.filter(id=>!hs.has(id)&&id!=="void-toast"&&!cmpLegacy.has(id));
t("All "+ji.length+" refs",mi.length===0);
if(mi.length)console.log("    "+mi.join(", "));

S("4. Button Parity");
const rq=["close","title","to-rep","cmp-l","cmp-r","poc","notes","curl","fetch","python","render"];
["hist","tgt","ep","log","sens"].forEach(p=>{const b=(html.match(new RegExp('id="'+p+'-detail-([^"]+)"',"g"))||[]).map(m=>m.match(/-detail-([^"]+)/)[1]);t(p,rq.filter(x=>!b.includes(x)).length===0);});
["path","httpver","to-rep","to-intr","cmp-l","cmp-r","to-poc","to-notes","open","reflect-hl","render","curl","fetch","python"].forEach(n=>t("ed-"+n,html.includes('id="ed-'+n+'"')));
["path","httpver","to-intr","cmp-l","cmp-r","to-poc","to-notes","open","reflect-hl","detail-render","detail-curl","detail-fetch","detail-python"].forEach(n=>t("rep-"+n,html.includes('id="rep-'+n+'"')));

S("5. Action Bars");
["hist","tgt","ep","rep","intr","log","sens","ed"].forEach(b=>t(b+"-reflect-bar",html.includes('id="'+b+'-reflect-bar"')));
const cb=(html.match(/type="checkbox"/g)||[]).length,tk=(html.match(/toggle-track/g)||[]).length;
t("Toggles "+cb+"="+tk,cb===tk);

S("6. Themes");
["theme-light","theme-dracula","theme-hacker"].forEach(th=>t(th,css.includes(th)));
["--tint-green","--tint-yellow","--tint-blue","--tint-red"].forEach(v=>t(v,css.includes("var("+v+")")));

S("7. Features");
const ft={"WS":["ws-filter","ws-tbody"],"Seq":["seq-url","seq-start"],"Notes":["notes-add","notes-form-save"],"PoC":["poc-csrf-technique","poc-cj-technique"],"Scan":["scan-url","scan-start"],"OOB":["oob-server","oob-register"],"Denc":["dec-chain-add","dec-saved-sel"],"RespInt":["resp-ed-status","btn-intercept-resp"],"Profiles":["cfg-profiles","cfg-profile-save"],"ReqView":["ed-path","rep-path"],"RepCompare":["rep-compare-toggle","rep2-method","rep2-send","rep-diff"],"APISchema":["schema-generate","schema-spec","schema-tree"],"CollabEverywhere":["cfg-collab-url","cfg-collab-enable"]};
Object.entries(ft).forEach(([n,e])=>{t(n,e.every(id=>html.includes('id="'+id+'"')));});

S("8. Background.js");
["GET_WS_HISTORY","GET_INTERCEPTED_RESPONSES","FORWARD_RESPONSE","DROP_RESPONSE","SET_INTERCEPT_RESPONSES"].forEach(m=>t(m,bg.includes(m)));
["webSocketCreated","webSocketFrameSent","webSocketFrameReceived","webSocketClosed"].forEach(e=>t(e,bg.includes(e)));
t("fulfillRequest",bg.includes("Fetch.fulfillRequest"));
t("Response stage",bg.includes('requestStage: "Response"'));

S("9. MD5");
vm.runInThisContext(xfn(js.substring(js.indexOf("function md5(str)"))));
[["","d41d8cd98f00b204e9800998ecf8427e"],["hello","5d41402abc4b2a76b9719d911017c592"],["test","098f6bcd4621d373cade4e832627b4f6"],["abc","900150983cd24fb0d6963f7d28e17f72"]].forEach(([i,e])=>t("md5("+i+")",md5(i)===e));

S("10. Decoder");
vm.runInThisContext(xfn(js.substring(js.indexOf("function decOp(op, input)"))));
t("b64e",decOp("b64-enc","hello")==="aGVsbG8=");
t("b64d",decOp("b64-dec","aGVsbG8=")==="hello");
t("urle",decOp("url-enc","a b")==="a%20b");
t("urld",decOp("url-dec","a%20b")==="a b");
t("md5d",decOp("md5","hello")==="5d41402abc4b2a76b9719d911017c592");
t("lc",decOp("lowercase","HI")==="hi");
t("uc",decOp("uppercase","hi")==="HI");
t("rt-b64",decOp("b64-dec",decOp("b64-enc","x"))==="x");
t("rt-url",decOp("url-dec",decOp("url-enc","a b"))==="a b");

S("11. XSS Escaping");
vm.runInThisContext(xfn(js.substring(js.indexOf("function pocEscHtml"))));
vm.runInThisContext(xfn(js.substring(js.indexOf("function pocEscJs"))));
t("html<",!pocEscHtml("<s>").includes("<"));
t('html"',!pocEscHtml('"').includes('"'));
t("html'",!pocEscHtml("'").includes("'"));
t("js</",!pocEscJs("</script>").includes("</s"));

S("12. URL Helpers");
vm.runInThisContext(xfn(js.substring(js.indexOf("function decomposeUrl"))));
vm.runInThisContext(xfn(js.substring(js.indexOf("function recomposeUrl"))));
vm.runInThisContext(xfn(js.substring(js.indexOf("function ensureHostHeader"))));
vm.runInThisContext(xfn(js.substring(js.indexOf("function extractHostFromHeaders"))));
vm.runInThisContext(xfn(js.substring(js.indexOf("function buildRawRequest"))));
vm.runInThisContext(xfn(js.substring(js.indexOf("function parseRawRequest"))));
const d1=decomposeUrl("https://x.com/a?q=1");
t("decomp",d1.scheme==="https"&&d1.host==="x.com"&&d1.path==="/a?q=1");
t("recomp",recomposeUrl("https","x.com","/a")==="https://x.com/a");
t("ensure",ensureHostHeader("CT: t","x.com").includes("Host: x.com"));
t("extract",extractHostFromHeaders("Host: x.com\nO: v")==="x.com");
const p1=parseRawRequest("GET /p HTTP/2\nH: x\n\nbody");
t("parse",p1.method==="GET"&&p1.path==="/p"&&p1.body==="body");

S("13. Session");
["notes","wsFrames","sequencer","scanFindings","intrGrep","decoderChain"].forEach(f=>{t("save "+f,js.includes(f+":"));t("load "+f,js.includes("data."+f));});

S("14. Rules");
vm.runInThisContext(rules);
t("Count "+SENSITIVE_RULES.length,SENSITIVE_RULES.length>50);
["cookie-no-secure","cookie-no-httponly","mixed-content","no-sri","crlf-indicator"].forEach(r=>t(r,SENSITIVE_RULES.some(x=>x.id===r)));

S("15. Scanner");
["sqli","xss","pathtraversal","ssrf","ssti","cmdi","openredirect","headerinject"].forEach(m=>t(m,js.includes(m+":")));

S("16. Misc");
["initKeyboardShortcuts","exportHar","autoDetectScope","showToast","voidSettingsProfiles","voidDecChains"].forEach(f=>t(f,js.includes(f)));

S("17. CSS");
["detail-action-bar","rep-view-pane","path-inp","httpver-sel","void-toast","dec-chain-step","dec-saved-bar","poc-layout","seq-layout","note-card","scan-config","oob-interactions","ws-conn-bar","render-frame","toggle-track"].forEach(c=>t("."+c,css.includes(c)));

console.log("\n"+"=".repeat(60));
console.log("RESULTS: "+P+" PASS, "+F+" FAIL");
console.log("=".repeat(60));
process.exit(F>0?1:0);

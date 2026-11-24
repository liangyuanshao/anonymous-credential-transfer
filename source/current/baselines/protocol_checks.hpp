#pragma once
#include "uprove/uprove.hpp"
#ifndef OTAC_USE_P256
#include "chan_yuen_2022/chan_yuen.hpp"
#endif
namespace baseline_checks {
using namespace otac;
inline std::vector<S> attributes(int n){
 std::vector<S>a;for(int i=0;i<n;i++){Hash h("otac/shared-benchmark-attributes/v1");h.u32(n);h.u32(i);h.blob("synthetic attribute=value");a.push_back(h.finish());}return a;
}
inline int uprove_checks(){
 int count=0;auto check=[&](bool b,const std::string&m){require(b,"U-Prove: "+m);count++;};
 for(int n:{4,16}){
  PP common(n);uprove::Params p(common);auto a=attributes(n);
  for(int d:{1,n/2,n}){
   auto req=request(a,d);auto i=uprove::issuer_first(p,a);auto u=uprove::user_second(p,a,i.msg);
   auto c=uprove::user_finish(p,u,uprove::issuer_third(p,i,u.challenge));
   check(uprove::token_verify(p,c.token),"signature completeness");
   const std::string context="verifier=benchmark;nonce=synthetic-unique-session";
   auto s=uprove::present(p,c,a,req,context);std::set<std::string>spent;
   check(uprove::verify(p,req,s,context,spent),"selective attributes");
   check(!uprove::verify(p,req,s,context,spent),"one-spend wrapper rejects replay");
   auto fresh=uprove::present(p,c,a,req,context);
   check(!uprove::verify(p,req,fresh,context,spent),"fresh proof cannot spend same token twice");
   auto reject=[&](const uprove::Presentation&bad,const Req&r,const std::string&ctx){std::set<std::string>empty;return !uprove::verify(p,r,bad,ctx,empty)&&empty.empty();};
   auto bad=s;bad.r0=bad.r0+S(1);check(reject(bad,req,context),"wrong token secret");
   bad=s;bad.token.r=bad.token.r+S(1);check(reject(bad,req,context),"signature tampering");
   auto wrong=req;wrong.values[0]=wrong.values[0]+S(1);check(reject(s,wrong,context),"wrong attribute request");
   check(reject(s,req,context+"-other"),"session binding");
   auto j=uprove::issuer_first(p,a);auto v=uprove::user_second(p,a,j.msg);
   auto other=uprove::user_finish(p,v,uprove::issuer_third(p,j,v.challenge));
   check(uprove::token_id(other.token)!=uprove::token_id(c.token),"distinct token IDs");
  }
 }
 return count;
}
#ifndef OTAC_USE_P256
inline int chan_yuen_checks(){
 int count=0;auto check=[&](bool b,const std::string&m){require(b,"Chan-Yuen: "+m);count++;};
 cy22::Paillier he;
 check(he.field(he.decrypt_signed(he.encrypt(cy22::Z(-17))))==S(-17),"signed plaintext encoding");
 for(int n:{4,16}){
  PP common(n);cy22::Params p(common);auto a=attributes(n);
  for(int d:{1,n/2,n}){
   auto req=request(a,d);auto h=cy22::user_request(p,a);
   check(cy22::request_verify(p,h.req,a),"request opening proof");
   auto badreq=h.req;badreq.z=badreq.z+S(1);check(!cy22::request_verify(p,badreq,a),"request proof tampering");
   auto i=cy22::issuer_first_core(p,he,h.req,a);cy22::user_mta_core(he,i,h);
   auto partial=cy22::issuer_finish_core(p,he,i,h.req,h);
   check(partial.beta==(p.x+i.delta+h.tp)*(i.u1+h.u2),"MtA field identity");
   auto c=cy22::user_finish(p,h,partial,a);check(cy22::credential_verify(p,c),"CL signature completeness");
   auto show=cy22::present(p,c,req);std::set<std::string>spent;
   check(cy22::verify(p,req,show,spent),"AND subset proof");
   check(!cy22::verify(p,req,show,spent),"experimental replay wrapper");
   auto reject=[&](const cy22::Presentation&s,const Req&r){std::set<std::string>empty;return !cy22::verify(p,r,s,empty)&&empty.empty();};
   auto bad=show;bad.W=bad.W*p.a;check(reject(bad,req),"AND witness tampering");
   bad=show;bad.credential.s=bad.credential.s+S(1);check(reject(bad,req),"signature tampering");
   auto wrong=req;wrong.values[0]=wrong.values[0]+S(1);check(reject(show,wrong),"wrong requested attribute");
  }
 }
 return count;
}
#endif
} // namespace baseline_checks

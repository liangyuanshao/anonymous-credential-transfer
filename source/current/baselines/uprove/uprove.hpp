#pragma once
#include "../../src/core.hpp"

// Algebraic reproduction of U-Prove 1.1 rev.5, sections 2.3--2.5.
// Uses the common PBC group and experiment transcript codec, NOT the recommended
// U-Prove parameters/hash encoding. Official interoperable code is in upstream/.
namespace uprove {
using namespace otac;
struct Params {
 const PP& p; G gt; S xt; std::string ti,pi;
 explicit Params(const PP& pp):p(pp),gt(G::hash("uprove-pbc/gt")),ti("single-credential-benchmark/v1") {
  gt.prepare();
  Hash h("uprove-pbc/token-information");h.blob(p.id);h.blob(ti);xt=h.finish();
 }
 G gamma(const std::vector<S>&a)const{return p.issuer_pk*p.attr_product(a)*pow(gt,xt);}
};
struct First {G z,a,b;std::string bytes()const{return z.bytes()+a.bytes()+b.bytes();}};
struct IssuerState {S w;First msg;};
struct Token {
 G h,z;S c,r;std::string uidp,ti,pi;
 std::string bytes()const{return uidp+h.bytes()+ti+pi+z.bytes()+c.bytes()+r.bytes();}
};
struct UserState {S alpha,beta1,beta2,challenge;G ap,bp;Token token;};
struct Credential {Token token;S alpha_inverse;};
inline S signature_hash(const Token&t,const G&a,const G&b){
 Hash h("uprove-pbc/token-signature/v1");h.point(t.h);h.blob(t.pi);h.point(t.z);h.point(a);h.point(b);return h.finish();
}
inline IssuerState issuer_first(const Params&p,const std::vector<S>&a){
 IssuerState i;i.w=S::random();G gamma=p.gamma(a);
 i.msg={pow(gamma,p.p.issuer_sk),pow(p.p.g,i.w),pow(gamma,i.w)};return i;
}
inline UserState user_second(const Params&p,const std::vector<S>&a,const First&m){
 UserState u;u.alpha=S::random(true);u.beta1=S::random();u.beta2=S::random();
 u.token.h=pow(p.gamma(a),u.alpha);u.token.z=pow(m.z,u.alpha);
 u.token.uidp=p.p.id;u.token.ti=p.ti;u.token.pi=p.pi;
 u.ap=pow(p.p.issuer_pk,u.beta1)*pow(p.p.g,u.beta2)*m.a;
 u.bp=pow(u.token.z,u.beta1)*pow(u.token.h,u.beta2)*pow(m.b,u.alpha);
 u.token.c=signature_hash(u.token,u.ap,u.bp);u.challenge=u.token.c+u.beta1;return u;
}
inline S issuer_third(const Params&p,const IssuerState&i,const S&challenge){return i.w+challenge*p.p.issuer_sk;}
inline bool token_verify(const Params&p,const Token&t){
 if(t.h.identity()||t.uidp!=p.p.id||t.ti!=p.ti||t.pi!=p.pi)return false;
 G a=pow(p.p.g,t.r)/pow(p.p.issuer_pk,t.c);
 G b=pow(t.h,t.r)/pow(t.z,t.c);
 return signature_hash(t,a,b)==t.c;
}
inline Credential user_finish(const Params&p,const UserState&u,const S&r){
 Credential c;c.token=u.token;c.token.r=r+u.beta2;c.alpha_inverse=u.alpha.inv();
 // Equivalent to the combined issuance validation in the reference createTokens.
 require(u.ap*u.bp==pow(p.p.g*c.token.h,c.token.r)/pow(p.p.issuer_pk*c.token.z,c.token.c),"U-Prove issuance rejected");return c;
}
inline std::string token_id(const Token&t){
 Hash h("uprove-pbc/token-id/v1");h.point(t.h);h.point(t.z);h.scalar(t.c);h.scalar(t.r);return h.finish().bytes();
}
struct Presentation {
 Token token;S a,r0;std::vector<S>r;
 std::string proof_bytes()const{std::string out=a.bytes()+r0.bytes();for(auto&x:r)out+=x.bytes();return out;}
 std::string bytes()const{return token.bytes()+proof_bytes();}
};
inline S presentation_hash(const Params&p,const Token&t,const Req&r,const S&a,const std::string&context){
 Hash h("uprove-pbc/subset-presentation/v1");h.blob(p.p.id);h.blob(token_id(t));h.scalar(a);bind_req(h,r);h.blob(context);return h.finish();
}
inline S commitment_hash(const G&a){Hash h("uprove-pbc/presentation-commitment/v1");h.point(a);return h.finish();}
inline Presentation present(const Params&p,const Credential&cred,const std::vector<S>&attrs,const Req&r,const std::string&context){
 for(size_t k=0;k<r.indices.size();k++)require(attrs.at(r.indices[k])==r.values[k],"U-Prove unsatisfied policy");
 auto hidden=hidden_indices(attrs.size(),r);S w0=S::random();std::vector<G>b;std::vector<S>w;
 for(int k:hidden){b.push_back(p.p.attrs[k]);w.push_back(S::random());}
 Presentation s;s.token=cred.token;s.a=commitment_hash(pow(s.token.h,w0)*msm(b,w));
 S c=presentation_hash(p,s.token,r,s.a,context);s.r0=w0+c*cred.alpha_inverse;
 for(size_t k=0;k<hidden.size();k++)s.r.push_back(w[k]-c*attrs[hidden[k]]);
 return s;
}
inline bool verify_core(const Params&p,const Req&r,const Presentation&s,const std::string&context){
 if(!token_verify(p,s.token))return false;
 auto hidden=hidden_indices(p.p.attrs.size(),r);if(s.r.size()!=hidden.size())return false;
 std::vector<G>b;for(int k:hidden)b.push_back(p.p.attrs[k]);
 S c=presentation_hash(p,s.token,r,s.a,context);
 G q=p.p.issuer_pk*public_product(p.p,r)*pow(p.gt,p.xt);
 return commitment_hash(pow(q,-c)*pow(s.token.h,s.r0)*msm(b,s.r))==s.a;
}
inline bool verify(const Params&p,const Req&r,const Presentation&s,const std::string&context,std::set<std::string>&spent){
 if(!verify_core(p,r,s,context))return false;
 // Experimental one-spend wrapper, not an extra claim about the core standard.
 return spent.insert(token_id(s.token)).second;
}
} // namespace uprove

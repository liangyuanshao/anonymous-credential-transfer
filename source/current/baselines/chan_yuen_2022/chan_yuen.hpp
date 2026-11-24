#pragma once
#include "pairing.hpp"
#include "paillier.hpp"

// Chan--Yuen, CANS 2022, sections 4.1--4.2 and 6.1.1 / Appendix E.1.
// The issuance implemented here is explicitly the honest-party CORE, not the
// complete malicious-secure issuance: pi_U and HE range/key proofs are absent.
namespace cy22 {
inline std::vector<S> encode_poly(const std::vector<S>&roots){
 std::vector<S>c{S(1)};
 for(auto&m:roots){std::vector<S>next(c.size()+1);for(size_t j=0;j<c.size();j++){next[j]=next[j]+m*c[j];next[j+1]=next[j+1]+c[j];}c=std::move(next);}return c;
}
struct Params {
 const PP& p;G a,b,c;G2 g2,X;std::vector<G>aj;std::vector<G2>Xj;S x;
 Params(const PP&pp):p(pp),a(G::hash("cy22/a")),b(G::hash("cy22/b")),c(G::hash("cy22/c")),g2(G2::generator()),x(S::random(true)){
  a.prepare();b.prepare();c.prepare();g2.prepare();
  S xp=S::random(true),v(1);X=pow(g2,x);
  // n public attributes plus one private opening root; polynomial degree n+1.
  for(size_t j=0;j<=p.attrs.size()+1;j++){aj.push_back(pow(a,v));Xj.push_back(pow(g2,v));v=v*xp;}
 }
 G commit(const std::vector<S>&attrs,const S&o)const{auto roots=attrs;roots.push_back(o);return msm(aj,encode_poly(roots));}
};
// msm in core requires equal vector lengths; a polynomial can use a prefix.
inline G commit_coeff(const Params&p,const std::vector<S>&coeff){
 require(coeff.size()<=p.aj.size(),"MoniPoly degree exceeds setup");std::vector<G>b(p.aj.begin(),p.aj.begin()+coeff.size());return msm(b,coeff);
}
inline G commitment(const Params&p,const std::vector<S>&attrs,const S&o){auto roots=attrs;roots.push_back(o);return commit_coeff(p,encode_poly(roots));}
struct Request {G C,M,A;S o,z;std::string bytes()const{return C.bytes()+M.bytes()+o.bytes()+A.bytes()+z.bytes();}};
struct HolderState {S s1,o,tp,u2,gamma2,omega2;Z z1;Request req;};
inline S request_hash(const Params&p,const Request&r){Hash h("cy22/pi-s/v1");h.blob(p.p.id);h.point(p.a);h.point(p.b);h.point(p.c);h.point(r.C);h.point(r.M);h.scalar(r.o);h.point(r.A);return h.finish();}
inline HolderState user_request(const Params&p,const std::vector<S>&attrs){
 HolderState h;h.o=S::random();h.s1=S::random();h.req.o=h.o;
 h.req.C=commitment(p,attrs,h.o);h.req.M=h.req.C*pow(p.b,h.s1);
 S w=S::random();h.req.A=pow(p.b,w);h.req.z=w+request_hash(p,h.req)*h.s1;return h;
}
inline bool request_verify(const Params&p,const Request&r,const std::vector<S>&attrs){
 return r.C==commitment(p,attrs,r.o)&&pow(p.b,r.z)==r.A*pow(r.M/r.C,request_hash(p,r));
}
struct IssuerState {S u1,delta;Z zu1,zx;};
inline IssuerState issuer_first_core(const Params&p,const Paillier&he,const Request&r,const std::vector<S>&attrs){
 require(request_verify(p,r,attrs),"Chan-Yuen credential request rejected");IssuerState i;
 i.u1=S::random(true);i.delta=S::random();i.zu1=he.encrypt(Z(i.u1));i.zx=he.encrypt(Z(p.x+i.delta));return i;
}
inline void user_mta_core(const Paillier&he,const IssuerState&i,HolderState&h){
 h.tp=S::random();h.u2=S::random(true);h.gamma2=S::random();h.omega2=h.gamma2+h.tp*h.u2;
 h.z1=he.add(he.add(he.multiply_plain(i.zu1,h.tp),he.multiply_plain(i.zx,h.u2)),he.encrypt(Z(0)-Z(h.gamma2)));
 // pi_U(t',u2,gamma2) is not instantiated by the source paper and is NOT
 // replaced by a boolean stub. Core-only status is exported with every row.
}
struct Partial {S delta,s2,beta;G v1;std::string bytes()const{return delta.bytes()+s2.bytes()+v1.bytes()+beta.bytes();}};
inline Partial issuer_finish_core(const Params&p,const Paillier&he,const IssuerState&i,const Request&r,const HolderState&h){
 S gamma1=he.field(he.decrypt_signed(h.z1));Partial out;
 out.beta=gamma1+(p.x+i.delta)*i.u1+h.omega2;
 require(out.beta!=S(),"zero MtA beta: restart issuance");out.delta=i.delta;out.s2=S::random();
 out.v1=pow(r.M*pow(p.b,out.s2)*p.c,i.u1*out.beta.inv());return out;
}
struct Credential {S t,s,o;G C,v;std::vector<S>attrs;std::string bytes()const{return C.bytes()+t.bytes()+s.bytes()+v.bytes();}};
inline bool credential_verify(const Params&p,const Credential&c){
 if(c.C.identity()||c.v.identity())return false;
 return pairing_equal(c.v,p.X*pow(p.g2,c.t),c.C*pow(p.b,c.s)*p.c,p.g2);
}
inline Credential user_finish(const Params&p,const HolderState&h,const Partial&i,const std::vector<S>&attrs){
 Credential c;c.t=h.tp+i.delta;c.s=h.s1+i.s2;c.o=h.o;c.C=h.req.C;c.attrs=attrs;
 c.v=i.v1*pow(h.req.M*pow(p.b,i.s2)*p.c,h.u2*i.beta.inv());
 require(credential_verify(p,c),"Chan-Yuen final signature rejected");return c;
}
struct Presentation {
 Credential credential;G W;
 std::string proof_bytes()const{return W.bytes();}
 std::string bytes()const{return credential.bytes()+W.bytes();}
};
inline Presentation present(const Params&p,const Credential&c,const Req&r){
 for(size_t k=0;k<r.indices.size();k++)require(c.attrs.at(r.indices[k])==r.values[k],"Chan-Yuen unsatisfied AND policy");
 auto hidden=hidden_indices(c.attrs.size(),r);std::vector<S>roots;for(int k:hidden)roots.push_back(c.attrs[k]);roots.push_back(c.o);
 Presentation s;s.credential=c;s.W=commit_coeff(p,encode_poly(roots));return s;
}
inline bool verify_core(const Params&p,const Req&r,const Presentation&s){
 if(!credential_verify(p,s.credential))return false;
 auto coeff=encode_poly(r.values);return pairing_equal(s.W,msm2(p.Xj,coeff),s.credential.C,p.g2);
}
inline std::string token_id(const Credential&c){
 // Stable v, not the malleable s,C representation; this wrapper is not in paper.
 Hash h("cy22/experimental-consumption-key/v1");h.point(c.v);return h.finish().bytes();
}
inline bool verify(const Params&p,const Req&r,const Presentation&s,std::set<std::string>&spent){
 if(!verify_core(p,r,s))return false;
 return spent.insert(token_id(s.credential)).second;
}
} // namespace cy22

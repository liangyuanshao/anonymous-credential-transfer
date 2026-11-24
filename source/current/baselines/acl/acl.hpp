#pragma once
#include "../../src/core.hpp"
namespace acl {
using namespace otac;
struct Registration{
 G C,A;S zx,zr;
 std::string bytes(const Opening&o)const{std::string b=C.bytes();for(auto&a:o.a)b+=a.bytes();return b+A.bytes()+zx.bytes()+zr.bytes();}
};
inline S reg_hash(const PP&p,const Registration&r,const std::vector<S>&a){
 Hash h("acl/registration-opening/v1");h.blob(p.id);h.point(r.C);for(auto&s:a)h.scalar(s);h.point(r.A);return h.finish();
}
inline Registration register_user(const PP&p,const Opening&o){
 Registration r;r.C=pow(p.acl_random,o.r)*pow(p.h0,o.x)*p.attr_product(o.a);
 S ux=S::random(),ur=S::random();r.A=pow(p.acl_random,ur)*pow(p.h0,ux);
 S c=reg_hash(p,r,o.a);r.zx=ux+c*o.x;r.zr=ur+c*o.r;return r;
}
inline bool register_verify(const PP&p,const Registration&r,const std::vector<S>&a){
 S c=reg_hash(p,r,a);return pow(p.acl_random,r.zr)*pow(p.h0,r.zx)==r.A*pow(r.C/p.attr_product(a),c);
}
struct IssuerState{
 S rnd,u,cp,rp1,rp2;G z1,z2,a,b1,b2;
};
struct UserState{
 S gamma,tau,t1,t2,t3,t4,t5,e;
 G zeta,zeta1,zeta2;
 std::string m;
};
struct Reply{S c,r,cp,rp1,rp2;};
struct Token{
 G zeta,zeta1;S rho,omega,rho1,rho2,omegap,mu;
 std::string m;
 std::string bytes()const{return m+zeta.bytes()+zeta1.bytes()+rho.bytes()+omega.bytes()+rho1.bytes()+rho2.bytes()+omegap.bytes()+mu.bytes();}
};
inline S signature_hash(const Token&t,const G&a,const G&a1,const G&a2,const G&eta){
 Hash h("acl/signature/v1");h.point(t.zeta);h.point(t.zeta1);h.point(a);h.point(a1);h.point(a2);h.point(eta);h.blob(t.m);return h.finish();
}
inline IssuerState issuer_prepare(const PP&p,const Registration&r,const std::vector<S>&a,bool check_registration=true){
 if(check_registration)require(register_verify(p,r,a),"ACL registration rejected");
 IssuerState s;s.rnd=S::random(true);s.z1=r.C*pow(p.g,s.rnd);s.z2=p.z/s.z1;
 s.u=S::random();s.cp=S::random();s.rp1=S::random();s.rp2=S::random();
 s.a=pow(p.g,s.u);s.b1=pow(p.g,s.rp1)*pow(s.z1,s.cp);s.b2=pow(p.h,s.rp2)*pow(s.z2,s.cp);return s;
}
inline UserState user_prepare(const PP&p,const Registration&r,const IssuerState&i){
 require(i.rnd!=S(),"ACL requires nonzero rnd");
 UserState u;u.gamma=S::random(true);u.tau=S::random();
 u.t1=S::random();u.t2=S::random();u.t3=S::random();u.t4=S::random();u.t5=S::random();
 u.zeta=pow(p.z,u.gamma);u.zeta1=pow(r.C*pow(p.g,i.rnd),u.gamma);u.zeta2=u.zeta/u.zeta1;
 G a=i.a*pow(p.g,u.t1)*pow(p.issuer_pk,u.t2);
 G a1=pow(i.b1,u.gamma)*pow(p.g,u.t3)*pow(u.zeta1,u.t4);
 G a2=pow(i.b2,u.gamma)*pow(p.h,u.t5)*pow(u.zeta2,u.t4);
 G eta=pow(p.z,u.tau);
 u.m=std::string(32,'\0');require(RAND_bytes(reinterpret_cast<unsigned char*>(u.m.data()),32)==1,"ACL message randomness");
 Token tmp;tmp.zeta=u.zeta;tmp.zeta1=u.zeta1;tmp.m=u.m;
 u.e=signature_hash(tmp,a,a1,a2,eta)-u.t2-u.t4;return u;
}
inline Reply issuer_reply(const PP&p,const IssuerState&i,const UserState&u){
 Reply r;r.c=u.e-i.cp;r.r=i.u-r.c*p.issuer_sk;r.cp=i.cp;r.rp1=i.rp1;r.rp2=i.rp2;return r;
}
inline Token user_finish(const UserState&u,const Reply&r){
 Token t;t.m=u.m;t.zeta=u.zeta;t.zeta1=u.zeta1;t.rho=r.r+u.t1;t.omega=r.c+u.t2;
 t.rho1=u.gamma*r.rp1+u.t3;t.rho2=u.gamma*r.rp2+u.t5;t.omegap=r.cp+u.t4;t.mu=u.tau-t.omegap*u.gamma;return t;
}
inline bool token_verify(const PP&p,const Token&t){
 if(t.zeta.identity()||t.m.size()!=32)return false;
 G z2=t.zeta/t.zeta1;
 G a=pow(p.g,t.rho)*pow(p.issuer_pk,t.omega);
 G a1=pow(p.g,t.rho1)*pow(t.zeta1,t.omegap);
 G a2=pow(p.h,t.rho2)*pow(z2,t.omegap);
 G eta=pow(p.z,t.mu)*pow(t.zeta,t.omegap);
 return t.omega+t.omegap==signature_hash(t,a,a1,a2,eta);
}
struct Presentation {
 Token token;G A,B;S zu,zr,zrnd,zx;std::vector<S>za;
 std::string proof_bytes()const{std::string b=A.bytes()+B.bytes()+zu.bytes()+zr.bytes()+zrnd.bytes()+zx.bytes();for(auto&s:za)b+=s.bytes();return b;}
 std::string bytes()const{return token.bytes()+proof_bytes();}
};
inline S show_hash(const PP&p,const Req&r,const Presentation&s){
 Hash h("acl/blinded-attribute-opening/v1");h.blob(p.id);h.blob(s.token.bytes());bind_req(h,r);h.point(s.A);h.point(s.B);return h.finish();
}
// Linearize the blinded commitment using u=gamma^{-1}:
// zeta^u=z; zeta1^u g^{-rnd} h_R^{-r} h0^{-x} prod h_i^{-a_i}=P_S.
inline Presentation present(const PP&p,const Token&t,const Opening&o,const UserState&u,const IssuerState&i,const Req&r){
 for(size_t k=0;k<r.indices.size();k++)require(o.a[r.indices[k]]==r.values[k],"ACL unsatisfied attributes");
 Presentation s;s.token=t;S mu=S::random(),mr=S::random(),mb=S::random(),mx=S::random();
 auto hidden=hidden_indices(o.a.size(),r);std::vector<G>bases;std::vector<S>ma,exps;
 for(int k:hidden){ma.push_back(S::random());bases.push_back(p.attrs[k]);exps.push_back(-ma.back());}
 s.A=pow(t.zeta,mu);s.B=pow(t.zeta1,mu)*pow(p.g,-mb)*pow(p.acl_random,-mr)*pow(p.h0,-mx)*msm(bases,exps);
 S c=show_hash(p,r,s);s.zu=mu+c*u.gamma.inv();s.zr=mr+c*o.r;s.zrnd=mb+c*i.rnd;s.zx=mx+c*o.x;
 for(size_t k=0;k<hidden.size();k++)s.za.push_back(ma[k]+c*o.a[hidden[k]]);
 return s;
}
inline bool verify(const PP&p,const Req&r,const Presentation&s,std::set<std::string>&spent){
 if(!token_verify(p,s.token))return false;
 auto hidden=hidden_indices(p.attrs.size(),r);if(s.za.size()!=hidden.size())return false;
 S c=show_hash(p,r,s);
 if(pow(s.token.zeta,s.zu)!=s.A*pow(p.z,c))return false;
 std::vector<G>bases;std::vector<S>exps;
 for(size_t k=0;k<hidden.size();k++){bases.push_back(p.attrs[hidden[k]]);exps.push_back(-s.za[k]);}
 G check=pow(s.token.zeta1,s.zu)*pow(p.g,-s.zrnd)*pow(p.acl_random,-s.zr)*pow(p.h0,-s.zx)*msm(bases,exps);
 if(check!=s.B*pow(public_product(p,r),c))return false;
 // Application wrapper: ACL alone does not maintain a global spent registry.
 return spent.insert(s.token.m).second;
}
} // namespace acl

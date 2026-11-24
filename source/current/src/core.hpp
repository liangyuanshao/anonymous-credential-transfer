#pragma once
#ifdef OTAC_USE_P256
#include <gmp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#else
#include "pbc.h"
#endif
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace otac {
#ifndef OTAC_USE_P256
inline pairing_t pairing;
#endif
inline mpz_t order;
inline int order_bits=0, scalar_bytes=0;
inline void require(bool ok,const std::string& msg) {
 if(!ok) throw std::runtime_error(msg);
}
struct S {
 mutable mpz_t v;
 S(long x=0) {mpz_init_set_si(v,x);mpz_mod(v,v,order);}
 S(const S& o) {mpz_init_set(v,o.v);}
 S(S&& o) noexcept {mpz_init(v);mpz_swap(v,o.v);}
 ~S(){mpz_clear(v);}
 S& operator=(const S&o){mpz_set(v,o.v);return *this;}
 S& operator=(S&&o) noexcept {mpz_swap(v,o.v);return *this;}
 static S random(bool nonzero=false) {
  S s; std::vector<unsigned char> b(scalar_bytes);
  do {
   require(RAND_bytes(b.data(),int(b.size()))==1,"RAND_bytes failed");
   b[0]&=static_cast<unsigned char>(255>>(8*scalar_bytes-order_bits));
   mpz_import(s.v,b.size(),1,1,1,0,b.data());
  }while(mpz_cmp(s.v,order)>=0||(nonzero&&mpz_sgn(s.v)==0));
  return s;
 }
 std::string bytes() const {
  std::string out(scalar_bytes,'\0');size_t count=0;
  std::vector<unsigned char>b(scalar_bytes);
  mpz_export(b.data(),&count,1,1,1,0,v);
  if(count)std::memcpy(out.data()+scalar_bytes-count,b.data(),count);
  return out;
 }
 S inv()const{S r;require(mpz_invert(r.v,v,order)!=0,"zero scalar inverse");return r;}
 bool operator==(const S&o)const{return mpz_cmp(v,o.v)==0;}
 bool operator!=(const S&o)const{return !(*this==o);}
 unsigned digit(int shift,int width)const{
  unsigned r=0;for(int j=0;j<width;j++)r|=unsigned(mpz_tstbit(v,shift+j))<<j;return r;
 }
};
inline S operator+(const S&a,const S&b){S r;mpz_add(r.v,a.v,b.v);mpz_mod(r.v,r.v,order);return r;}
inline S operator-(const S&a,const S&b){S r;mpz_sub(r.v,a.v,b.v);mpz_mod(r.v,r.v,order);return r;}
inline S operator-(const S&a){S r;mpz_neg(r.v,a.v);mpz_mod(r.v,r.v,order);return r;}
inline S operator*(const S&a,const S&b){S r;mpz_mul(r.v,a.v,b.v);mpz_mod(r.v,r.v,order);return r;}

#ifdef OTAC_USE_P256
#include "group_p256.hpp"
#else
#include "group_arithmetic.hpp"
namespace curve_ops {
inline auto point_field(element_ptr point) { return curve_x_coord(point)->field; }
}

struct G {
 mutable element_t v;
 std::shared_ptr<curve_ops::FixedBase> fixed;
 G(){element_init_G1(v,pairing);element_set1(v);}
 G(const G&o):fixed(o.fixed){element_init_G1(v,pairing);element_set(v,o.v);}
 G(G&&o)noexcept:fixed(std::move(o.fixed)){element_init_G1(v,pairing);std::swap(v[0],o.v[0]);}
 ~G(){element_clear(v);}
 G&operator=(const G&o){element_set(v,o.v);fixed=o.fixed;return *this;}
 G&operator=(G&&o)noexcept{std::swap(v[0],o.v[0]);fixed.swap(o.fixed);return *this;}
 bool operator==(const G&o)const{return element_cmp(v,o.v)==0;}
 bool operator!=(const G&o)const{return !(*this==o);}
 bool identity()const{return element_is1(v)!=0;}
 void reset(){fixed.reset();element_set1(v);}
 void mul_in(const G&b){fixed.reset();element_mul(v,v,b.v);}
 void square(){fixed.reset();element_square(v,v);}
 void prepare(){if(!fixed&&!identity())fixed=std::make_shared<curve_ops::FixedBase>(v);}
 std::string bytes()const{
  int n=element_length_in_bytes_compressed(v);
  std::string out(n,'\0');
  // PBC has no portable infinity encoding; use a separately tagged fixed codec.
  if(identity()) return std::string(1,'\0')+out;
  element_to_bytes_compressed(reinterpret_cast<unsigned char*>(out.data()),v);
  return std::string(1,'\1')+out;
 }
 static G from_bytes(const std::string& b){
  G r;require(int(b.size())==1+element_length_in_bytes_compressed(r.v),"bad group length");
  if(b[0]==0){require(b==r.bytes(),"noncanonical identity");return r;}
  require(b[0]==1,"bad group tag");
  element_from_bytes_compressed(r.v,reinterpret_cast<const unsigned char*>(b.data()+1));
  require(r.bytes()==b,"noncanonical point");
  G check; element_pow_mpz(check.v,r.v,order);
  require(check.identity(),"point outside subgroup");return r;
 }
 static G hash(const std::string&s){
  std::array<unsigned char,64>d{};SHA512(reinterpret_cast<const unsigned char*>(s.data()),s.size(),d.data());
  G r;element_from_hash(r.v,d.data(),int(d.size()));require(!r.identity(),"hash point identity");return r;
 }
};
inline G operator*(const G&a,const G&b){G r;element_mul(r.v,a.v,b.v);return r;}
inline G operator/(const G&a,const G&b){G r;element_div(r.v,a.v,b.v);return r;}
inline G pow(const G&a,const S&s){G r;if(a.fixed)element_pp_pow(r.v,s.v,a.fixed->table);else curve_ops::power(r.v,a.v,s.v);return r;}
inline G inv(const G&a){G r;element_invert(r.v,a.v);return r;}
inline G msm(const std::vector<G>& bases,const std::vector<S>&s){
 require(bases.size()==s.size(),"MSM length mismatch");G out;
 std::vector<element_ptr> b;std::vector<mpz_ptr> e;b.reserve(bases.size());e.reserve(s.size());
 for(size_t i=0;i<bases.size();++i){b.push_back(bases[i].v);e.push_back(s[i].v);}
 curve_ops::multiexp(out.v,b,e);
 return out;
}
#endif
struct Hash {
 EVP_MD_CTX* c;
 explicit Hash(const std::string&dom):c(EVP_MD_CTX_new()){require(c&&EVP_DigestInit_ex(c,EVP_sha512(),nullptr)==1,"digest init");blob(dom);}
 ~Hash(){EVP_MD_CTX_free(c);}
 Hash(const Hash&)=delete;
 void raw(const std::string&s){require(EVP_DigestUpdate(c,s.data(),s.size())==1,"digest update");}
 void u32(uint32_t x){unsigned char b[4]={static_cast<unsigned char>(x>>24),static_cast<unsigned char>(x>>16),static_cast<unsigned char>(x>>8),static_cast<unsigned char>(x)};require(EVP_DigestUpdate(c,b,4)==1,"digest integer");}
 void blob(const std::string&s){u32(uint32_t(s.size()));raw(s);}
 void point(const G&g){blob(g.bytes());}
 void scalar(const S&s){blob(s.bytes());}
 S finish(){std::array<unsigned char,64>d;unsigned n=0;require(EVP_DigestFinal_ex(c,d.data(),&n)==1&&n==64,"digest final");S s;mpz_import(s.v,d.size(),1,1,1,0,d.data());mpz_mod(s.v,s.v,order);return s;}
};
#ifndef OTAC_USE_P256
inline void secure_pbc_random(mpz_t out,mpz_t limit,void*){
 int bits=mpz_sizeinbase(limit,2),n=(bits+7)/8;std::vector<unsigned char>b(n);
 do{require(RAND_bytes(b.data(),n)==1,"PBC randomness failed");b[0]&=255>>(8*n-bits);mpz_import(out,n,1,1,1,0,b.data());}while(mpz_cmp(out,limit)>=0);
}
inline std::string read_file(const std::string&p){std::ifstream f(p,std::ios::binary);require(bool(f),"cannot open "+p);return {std::istreambuf_iterator<char>(f),{}};}
inline void init(const std::string&param){
 pbc_random_set_function(secure_pbc_random,nullptr);
 auto s=read_file(param);require(pairing_init_set_buf(pairing,s.data(),s.size())==0,"bad pairing params");
 require(!pairing_is_symmetric(pairing),"symmetric parameters violate the DDH setting");
 mpz_init_set(order,pairing->r);order_bits=mpz_sizeinbase(order,2);scalar_bytes=(order_bits+7)/8;
}
#endif
struct PP {
 G g,h0,h,acl_random,issuer_pk,z;
 std::vector<G> attrs;
 S issuer_sk;
 std::string id;
 explicit PP(int n):issuer_sk(S::random(true)){
  g=G::hash("otac/v1/g");h0=G::hash("otac/v1/h0");h=G::hash("otac/v1/acl-h");acl_random=G::hash("otac/v1/acl-random");
  for(int i=0;i<n;i++)attrs.push_back(G::hash("otac/v1/attribute/"+std::to_string(i)));
  g.prepare();h0.prepare();h.prepare();acl_random.prepare();
  issuer_pk=pow(g,issuer_sk);
  z=G::hash("acl/v1/tag-key/"+g.bytes()+h.bytes()+issuer_pk.bytes());
  issuer_pk.prepare();z.prepare();
  Hash hash("otac/v1/parameter-fingerprint");hash.point(g);hash.point(h0);hash.point(h);hash.point(acl_random);hash.point(issuer_pk);hash.point(z);
  for(auto&a:attrs)hash.point(a);
  id=hash.finish().bytes();
 }
 G attr_product(const std::vector<S>&a)const{return msm(attrs,a);}
};
struct Req {
 std::vector<int> indices;
 std::vector<S> values;
};
inline Req request(const std::vector<S>&a,int d){Req r;for(int i=0;i<d;i++){r.indices.push_back(i);r.values.push_back(a[i]);}return r;}
inline G public_product(const PP&p,const Req&r){std::vector<G>b;for(int i:r.indices){require(i>=0&&i<int(p.attrs.size()),"attribute index");b.push_back(p.attrs[i]);}return msm(b,r.values);}
inline std::vector<int> hidden_indices(int n,const Req&r){std::vector<int>out;for(int k=0;k<n;k++)if(std::find(r.indices.begin(),r.indices.end(),k)==r.indices.end())out.push_back(k);return out;}
inline void bind_req(Hash&h,const Req&r){h.u32(r.indices.size());for(size_t k=0;k<r.indices.size();k++){h.u32(r.indices[k]);h.scalar(r.values[k]);}}
struct Opening{S x,r;std::vector<S>a;};
inline Opening opening(int n){Opening o;o.x=S::random(true);o.r=S::random();for(int k=0;k<n;k++)o.a.push_back(S::random());return o;}
inline double timed(const std::function<void()>&f){auto t=std::chrono::steady_clock::now();f();return std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-t).count();}
struct Reg {
 G Y,C,A,B;S zx,zr;
 std::string proof_bytes()const{return A.bytes()+B.bytes()+zx.bytes()+zr.bytes();}
 std::string bytes(const Opening&o)const{
  std::string b=Y.bytes()+C.bytes();for(auto&a:o.a)b+=a.bytes();return b+proof_bytes();
 }
};
inline S reg_challenge(const PP&p,const Reg&r,const std::vector<S>&a,bool acl){
 Hash h(acl?"acl/registration/v1":"otac/registration/v1");h.blob(p.id);h.point(r.Y);h.point(r.C);
 for(auto&s:a)h.scalar(s);
 h.point(r.A);h.point(r.B);return h.finish();
}
inline Reg reg_gen(const PP&p,const Opening&o,bool acl=false){
 Reg r;r.Y=pow(p.h0,o.x);const G&b=acl?p.acl_random:p.g;
 r.C=pow(b,o.r)*r.Y*p.attr_product(o.a);S ux=S::random(),ur=S::random();
 r.A=pow(p.h0,ux);r.B=pow(b,ur);S c=reg_challenge(p,r,o.a,acl);
 r.zx=ux+c*o.x;r.zr=ur+c*o.r;return r;
}
inline bool reg_verify(const PP&p,const Reg&r,const std::vector<S>&a,bool acl=false){
 if(r.Y.identity()||a.size()!=p.attrs.size())return false;
 S c=reg_challenge(p,r,a,acl);G R=r.C/r.Y/p.attr_product(a);const G&b=acl?p.acl_random:p.g;
 return pow(p.h0,r.zx)==r.A*pow(r.Y,c)&&pow(b,r.zr)==r.B*pow(R,c);
}
} // namespace otac

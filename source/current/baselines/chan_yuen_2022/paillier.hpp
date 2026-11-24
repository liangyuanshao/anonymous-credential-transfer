#pragma once
#include "../../src/core.hpp"
#include <openssl/bn.h>

// Real GMP Paillier arithmetic for the section 4.2 honest-party core.
// No cryptosystem-specific range / well-formedness / multiplication proofs.
namespace cy22 {
using namespace otac;
struct Z {
 mpz_t v;
 Z(long n=0){mpz_init_set_si(v,n);}
 Z(const Z&o){mpz_init_set(v,o.v);}
 explicit Z(const S&s){mpz_init_set(v,s.v);}
 Z(Z&&o)noexcept{mpz_init(v);mpz_swap(v,o.v);}
 ~Z(){mpz_clear(v);}
 Z&operator=(const Z&o){mpz_set(v,o.v);return *this;}
 Z&operator=(Z&&o)noexcept{mpz_swap(v,o.v);return *this;}
 std::string bytes(size_t n)const{require(mpz_sgn(v)>=0,"negative integer encoding");require(mpz_sgn(v)==0||mpz_sizeinbase(v,2)<=8*n,"integer encoding overflow");size_t k=0;std::string out(n,'\0');std::vector<unsigned char>b(n);mpz_export(b.data(),&k,1,1,1,0,v);if(k)std::memcpy(out.data()+n-k,b.data(),k);return out;}
};
inline Z operator+(const Z&a,const Z&b){Z r;mpz_add(r.v,a.v,b.v);return r;}
inline Z operator-(const Z&a,const Z&b){Z r;mpz_sub(r.v,a.v,b.v);return r;}
inline Z operator*(const Z&a,const Z&b){Z r;mpz_mul(r.v,a.v,b.v);return r;}
inline Z mod(const Z&a,const Z&m){Z r;mpz_mod(r.v,a.v,m.v);return r;}
inline Z random_below(const Z&n){Z r;secure_pbc_random(r.v,const_cast<mpz_ptr>(n.v),nullptr);return r;}
inline Z modpow(const Z&a,const Z&e,const Z&m){Z r;mpz_powm(r.v,a.v,e.v,m.v);return r;}
inline Z prime(int bits){
 BIGNUM*b=BN_new();require(b&&BN_generate_prime_ex(b,bits,0,nullptr,nullptr,nullptr)==1,"Paillier prime generation");
 char*h=BN_bn2hex(b);Z p;require(h&&mpz_set_str(p.v,h,16)==0,"prime import");OPENSSL_free(h);BN_free(b);return p;
}
struct Paillier {
 Z n,n2,lambda,mu;size_t nbytes=0;
 explicit Paillier(int bits=3072){
  require(bits>=3072,"benchmark Paillier modulus must be at least 3072 bits");
  Z p=prime(bits/2),q=prime(bits-bits/2);while(mpz_cmp(p.v,q.v)==0)q=prime(bits-bits/2);
  n=p*q;n2=n*n;mpz_lcm(lambda.v,(p-Z(1)).v,(q-Z(1)).v);
  require(mpz_invert(mu.v,lambda.v,n.v)!=0,"Paillier inverse");
  nbytes=(mpz_sizeinbase(n.v,2)+7)/8;
  require(mpz_sizeinbase(n.v,2)>size_t(2*order_bits+4),"Paillier modulus too small for MtA integer products");
 }
 Z encrypt(const Z&m)const{
  Z rho,gcd;do{rho=random_below(n);mpz_gcd(gcd.v,rho.v,n.v);}while(mpz_cmp_ui(gcd.v,1)!=0);
  // g=1+n; (1+n)^m = 1+n*m mod n^2.
  return mod((Z(1)+n*mod(m,n))*modpow(rho,n,n2),n2);
 }
 Z decrypt_signed(const Z&c)const{
  require(mpz_sgn(c.v)>0&&mpz_cmp(c.v,n2.v)<0,"Paillier ciphertext range");
  Z u=modpow(c,lambda,n2)-Z(1);mpz_divexact(u.v,u.v,n.v);u=mod(u*mu,n);
  Z half;mpz_fdiv_q_2exp(half.v,n.v,1);if(mpz_cmp(u.v,half.v)>0)u=u-n;return u;
 }
 Z multiply_plain(const Z&c,const S&s)const{return modpow(c,Z(s),n2);}
 Z add(const Z&a,const Z&b)const{return mod(a*b,n2);}
 S field(const Z&z)const{S s;mpz_mod(s.v,z.v,order);return s;}
};
} // namespace cy22

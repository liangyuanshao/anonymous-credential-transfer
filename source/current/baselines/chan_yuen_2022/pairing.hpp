#pragma once
#include "../../src/core.hpp"
namespace cy22 {
using namespace otac;
struct G2 {
 mutable element_t v;
 std::shared_ptr<curve_ops::FixedBase> fixed;
 G2(){element_init_G2(v,pairing);element_set1(v);}
 G2(const G2&o):fixed(o.fixed){element_init_G2(v,pairing);element_set(v,o.v);}
 G2(G2&&o)noexcept:fixed(std::move(o.fixed)){element_init_G2(v,pairing);std::swap(v[0],o.v[0]);}
 ~G2(){element_clear(v);}
 G2&operator=(const G2&o){element_set(v,o.v);fixed=o.fixed;return *this;}
 G2&operator=(G2&&o)noexcept{std::swap(v[0],o.v[0]);fixed.swap(o.fixed);return *this;}
 void prepare(){if(!fixed&&!element_is1(v))fixed=std::make_shared<curve_ops::FixedBase>(v);}
 static G2 generator(){G2 g;element_random(g.v);require(!element_is1(g.v),"G2 identity");return g;}
 std::string bytes()const{int n=element_length_in_bytes_compressed(v);std::string b(n,'\0');if(element_is1(v))return std::string(1,'\0')+b;element_to_bytes_compressed(reinterpret_cast<unsigned char*>(b.data()),v);return std::string(1,'\1')+b;}
};
inline G2 pow(const G2&a,const S&s){G2 r;if(a.fixed)element_pp_pow(r.v,s.v,a.fixed->table);else curve_ops::power(r.v,a.v,s.v);return r;}
inline G2 operator*(const G2&a,const G2&b){G2 r;element_mul(r.v,a.v,b.v);return r;}
inline G2 msm2(const std::vector<G2>&b,const std::vector<S>&s){require(b.size()>=s.size(),"G2 polynomial too large");G2 r;std::vector<element_ptr>bases;std::vector<mpz_ptr>exps;for(size_t k=0;k<s.size();++k){bases.push_back(b[k].v);exps.push_back(s[k].v);}curve_ops::multiexp(r.v,bases,exps);return r;}
inline bool pairing_equal(const G&a,const G2&b,const G&c,const G2&d){
 element_t l,r;element_init_GT(l,pairing);element_init_GT(r,pairing);
 pairing_apply(l,a.v,b.v,pairing);pairing_apply(r,c.v,d.v,pairing);
 bool ok=element_cmp(l,r)==0;element_clear(l);element_clear(r);return ok;
}
} // namespace cy22

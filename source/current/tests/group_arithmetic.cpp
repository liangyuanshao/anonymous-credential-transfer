#include "../src/ours.hpp"
#include "../baselines/chan_yuen_2022/pairing.hpp"
using namespace otac;
static int checks=0;
static void same(bool ok,const std::string& message){require(ok,message);++checks;}
template<class Group> static Group native_power(const Group& p,const S& s){Group out;element_pow_mpz(out.v,p.v,s.v);return out;}
template<class Group> static void group_checks(const Group& generator){
 std::vector<S> scalars{S(),S(1),S(2),S(-1),S(-2)};
 for(int i=0;i<20;++i)scalars.push_back(S::random());
 for(const auto& s:scalars){auto x=pow(generator,s);auto y=native_power(generator,s);same(element_cmp(x.v,y.v)==0,"Jacobian scalar multiplication");}
 Group id;for(const auto& s:scalars)same(element_is1(pow(id,s).v),"identity scalar multiplication");
 auto fixed=generator;fixed.prepare();
 for(const auto& s:scalars){auto x=pow(fixed,s);auto y=native_power(generator,s);same(element_cmp(x.v,y.v)==0,"public fixed-base exponentiation");}
 for(int n:{0,1,2,3,4,7,8,16,32,64,65}){
  std::vector<Group>b;std::vector<S>e;
  for(int i=0;i<n;++i){
   if(i%5==0)b.emplace_back();
   else if(i%5==1)b.push_back(generator);
   else if(i%5==2)b.push_back(native_power(generator,S(-1)));
   else b.push_back(native_power(generator,S::random()));
   e.push_back(i%7==0?S():i%7==1?S(1):S::random());
  }
  Group expected,out;for(int i=0;i<n;++i){auto term=native_power(b[i],e[i]);element_mul(expected.v,expected.v,term.v);}
  std::vector<element_ptr> bases;std::vector<mpz_ptr> exps;
  for(int i=0;i<n;++i){bases.push_back(b[i].v);exps.push_back(e[i].v);}
  curve_ops::multiexp(out.v,bases,exps);same(element_cmp(out.v,expected.v)==0,"MSM against native PBC");
 }
 // Equal and opposite inputs exercise exceptional addition paths in buckets.
 for(bool opposite:{false,true}){
  Group q=native_power(generator,opposite?S(-1):S(1)),out,expected;
  std::vector<element_ptr>b{generator.v,q.v};S one(1);std::vector<mpz_ptr>e{one.v,one.v};
  curve_ops::multiexp(out.v,b,e);element_mul(expected.v,generator.v,q.v);
  same(element_cmp(out.v,expected.v)==0,"equal/opposite-point MSM");
 }
}
static void gk_checks(){
 PP base(4);scheme::Params p(base);
 const scheme::oom_windows::OddPowers powers(p.g);
 for(const auto& s:{S(),S(1),S(15),S(17),S(31),S(-1),S::random()}){
  auto evaluated=scheme::oom_windows::power(powers,scheme::oom_windows::recode(s));
  same(evaluated==native_power(p.g,s),"OoM signed windows against native PBC");
  same(p.g_comb.power(s)==native_power(p.g,s),"OoM comb for g against native PBC");
  same(p.k_comb.power(s)==native_power(p.k,s),"OoM comb for k against native PBC");
 }
 const scheme::oom_windows::AttributeProducts attributes(p.attrs);
 const std::vector<S> attr_exponents{S::random(),S(),S(17),S(-1)};
 same(attributes.full(attr_exponents)==p.attr_product(attr_exponents),"shared attribute table full product");
 same(attributes.subset({3,0},{attr_exponents[3],attr_exponents[0]})==
      native_power(p.attrs[3],attr_exponents[3])*native_power(p.attrs[0],attr_exponents[0]),
      "shared attribute table follows subset indices");
 same(attributes.subset({},{}).identity(),"empty attribute subset");
 const std::vector<std::pair<size_t,int>> cases{{2,0},{3,1},{8,0},{8,5},{64,37},{65,64}};
 for(const auto& [ell,index]:cases){
  std::vector<G> list;for(size_t i=0;i<ell;++i)list.push_back(G::hash("arithmetic-test/"+std::to_string(i)));
  S delta=S::random();G D=list[index]*pow(p.g,delta),q2=pow(p.k,delta);
  scheme::GKSecret w;auto first=scheme::gk_first(p,list,index,w);
  auto full=scheme::padded(list);size_t m=w.bits.size();std::vector<std::vector<S>>polynomials;
  for(size_t i=0;i<full.size();++i){
   std::vector<S> poly{S(1)};
   for(size_t j=0;j<m;++j){S constant=((i>>j)&1)?w.a[j]:-w.a[j];S leading(((i>>j)&1)?w.bits[j]:1-w.bits[j]);
    std::vector<S> next(poly.size()+1);for(size_t k=0;k<poly.size();++k){next[k]=next[k]+poly[k]*constant;next[k+1]=next[k+1]+poly[k]*leading;}poly=std::move(next);}
   polynomials.push_back(std::move(poly));
  }
  for(size_t k=0;k<m;++k){G left,right;S sum;
   for(size_t i=0;i<full.size();++i){sum=sum+polynomials[i][k];G term=native_power(D/full[i],polynomials[i][k]);element_mul(left.v,left.v,term.v);G t=native_power(q2,polynomials[i][k]);element_mul(right.v,right.v,t.v);}
   left=left*native_power(p.g,w.rho[k]);right=right*native_power(p.k,w.rho[k]);
   same(sum==S(),"GK coefficient cancellation");same(left==first.D[k].a&&right==first.D[k].b,"GK transcript equality with original statement");
  }
  for(const auto& challenge:{S(),S(1),S::random()}){
   auto proof=first;scheme::gk_respond(proof,w,delta,challenge);
   same(scheme::gk_verify(p,list,D,q2,proof,challenge),"GK composed equations");
   proof.D[0].a.mul_in(p.g);
   same(!scheme::gk_verify(p,list,D,q2,proof,challenge),"GK first coordinate remains binding");
   proof.D[0]=first.D[0];proof.D[0].b.mul_in(p.k);
   same(!scheme::gk_verify(p,list,D,q2,proof,challenge),"GK second coordinate remains binding");
  }
 }
}
int main(int argc,char**argv){try{
 require(argc==2,"usage: group_arithmetic_checks PARAM");init(argv[1]);
 group_checks(G::hash("arithmetic-g1"));group_checks(cy22::G2::generator());gk_checks();
 {G a=G::hash("cache-consistency"),b=G::hash("cache-factor");a.prepare();G copy=a;S e=S::random();
  a.mul_in(b);same(pow(a,e)==native_power(a,e),"cache invalidation on multiplication");
  same(pow(copy,e)==native_power(copy,e),"shared fixed-base copy remains unchanged");
  a.prepare();a.square();same(pow(a,e)==native_power(a,e),"cache invalidation on squaring");
  a.prepare();a.reset();same(pow(a,e).identity(),"cache invalidation on reset");}
 std::cout<<"PASS "<<checks<<" native equivalence and exceptional-point checks\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

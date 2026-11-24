#pragma once
#include "core.hpp"
#include "oom_fixed.hpp"
#include "oom_windows.hpp"
#include <mutex>

// Anonymous attribute credentials with consumption and transfer proofs.
namespace otac::scheme {
inline constexpr unsigned challenge_bits=128;
inline constexpr size_t max_candidates=1u<<20;
struct Params {
 const PP& base;G g,h0,k;std::vector<G> attrs;std::string id;
 const oom_fixed::Comb g_comb, k_comb;
 explicit Params(const PP& b):base(b),g(b.g),h0(b.h0),k(G::hash("otac/revised/v2/tag-base")),attrs(b.attrs),
  g_comb(g),k_comb(k){
  require(!attrs.empty()&&order_bits>int(challenge_bits),"bad revised parameters");std::set<std::string> seen;
  for(const auto& a:attrs)require(!a.identity()&&seen.insert(a.bytes()).second,"duplicate attribute base");
  for(const auto& a:{g,h0,k})require(!a.identity()&&seen.insert(a.bytes()).second,"duplicate public base");
  Hash h("otac/revised/v2/public-parameters");h.blob(b.id);h.point(k);h.u32(challenge_bits);id=h.finish().bytes();
 }
 G attr_product(const std::vector<S>& a)const{require(a.size()==attrs.size(),"attribute length");return msm(attrs,a);}
};
inline S challenge128(Hash& h){std::array<unsigned char,64>b{};unsigned n=0;require(EVP_DigestFinal_ex(h.c,b.data(),&n)==1&&n==64,"proof challenge digest");S c;mpz_import(c.v,challenge_bits/8,1,1,1,0,b.data());return c;}
inline void put_u32(std::string& out,uint32_t x){for(int i=3;i>=0;--i)out.push_back(char(x>>(8*i)));}
struct Reader {
 const std::string& in;size_t pos=0;explicit Reader(const std::string& b):in(b){}
 std::string take(size_t n){require(n<=in.size()-pos,"truncated protocol encoding");auto s=in.substr(pos,n);pos+=n;return s;}
 uint32_t u32(){auto b=take(4);uint32_t v=0;for(unsigned char c:b)v=(v<<8)|c;return v;}
 S scalar(){auto b=take(size_t(scalar_bytes));S s;mpz_import(s.v,b.size(),1,1,1,0,b.data());require(mpz_cmp(s.v,order)<0,"noncanonical scalar");return s;}
 G point(){
#ifdef OTAC_USE_P256
  return G::from_bytes(take(G::encoded_size));
#else
  G scratch;auto b=take(scratch.bytes().size());
  if(b[0]==0)return G::from_bytes(b);
  require(b[0]==1&&static_cast<unsigned char>(b.back())<=1,"bad compressed point tag or sign");
  // PBC's compressed decoder assumes sqrt(x^3+ax+b) exists. Check that
  // precondition before invoking it on bytes from an untrusted peer.
  auto x=curve_x_coord(scratch.v);size_t xsize=b.size()-2;
  mpz_t coordinate;mpz_init(coordinate);mpz_import(coordinate,xsize,1,1,1,0,b.data()+1);
  bool in_field=mpz_cmp(coordinate,x->field->order)<0;mpz_clear(coordinate);
  require(in_field,"curve coordinate outside base field");
  element_from_bytes(x,reinterpret_cast<const unsigned char*>(b.data()+1));
  std::string canonical(xsize,'\0');element_to_bytes(reinterpret_cast<unsigned char*>(canonical.data()),x);
  require(canonical==b.substr(1,xsize),"noncanonical curve coordinate");
  element_t rhs;element_init(rhs,x->field);element_square(rhs,x);element_add(rhs,rhs,curve_a_coeff(scratch.v));element_mul(rhs,rhs,x);element_add(rhs,rhs,curve_b_coeff(scratch.v));
  bool on_curve=element_is_sqr(rhs)!=0;element_clear(rhs);require(on_curve,"compressed coordinate is not on the curve");
  return G::from_bytes(b);
#endif
 }
 size_t count(size_t maximum){size_t n=u32();require(n<=maximum,"oversized vector");return n;}
 void done(){require(pos==in.size(),"trailing protocol bytes");}
};
inline size_t random_below(size_t n){require(n>0,"empty random range");uint64_t v=0,b=uint64_t(n),threshold=(uint64_t(0)-b)%b;do{require(RAND_bytes(reinterpret_cast<unsigned char*>(&v),sizeof(v))==1,"selection randomness");}while(v<threshold);return size_t(v%b);}
inline bool valid_request(const Params& p,const Req& r){if(r.indices.size()!=r.values.size()||r.indices.size()>p.attrs.size())return false;std::set<int>s;for(int i:r.indices)if(i<0||i>=int(p.attrs.size())||!s.insert(i).second)return false;return true;}
inline G public_product(const Params& p,const Req& r){require(valid_request(p,r),"bad service request");std::vector<G>b;for(int i:r.indices)b.push_back(p.attrs[i]);return msm(b,r.values);}
struct Opening {std::vector<S>a;S r;};
inline G commitment(const Params& p,const Opening& o){return pow(p.g,o.r)*p.attr_product(o.a);}
inline bool distinct_list(const std::vector<G>& list){if(list.size()<2||list.size()>max_candidates)return false;std::set<std::string>s;for(const auto& C:list)if(!s.insert(C.bytes()).second)return false;return true;}
struct Sig {
 G A;S z;
 std::string bytes()const{return A.bytes()+z.bytes();}
 static Sig from_bytes(const std::string& b){Reader r(b);Sig s;s.A=r.point();s.z=r.scalar();r.done();return s;}
};
inline S sig_challenge(const Params& p,const G& C,const G& A){Hash h("otac/revised/v2/schnorr-signature");h.blob(p.id);h.point(C);h.point(A);return h.finish();}
inline Sig sign(const Params& p,const G& C){Sig s;S nonce=S::random();s.A=pow(p.g,nonce);s.z=nonce+sig_challenge(p,C,s.A)*p.base.issuer_sk;return s;}
inline bool sig_verify(const Params& p,const G& C,const Sig& s){return pow(p.g,s.z)==s.A*pow(p.base.issuer_pk,sig_challenge(p,C,s.A));}
struct Credential {
 G C;Sig signature;
 std::string bytes()const{return C.bytes()+signature.bytes();}
 std::string payload_bytes()const{return bytes();}
 static Credential from_bytes(const std::string& b){Reader r(b);Credential c;c.C=r.point();c.signature.A=r.point();c.signature.z=r.scalar();r.done();return c;}
};
struct CredRequest {
 G Y,R,C,Ax,AR,AC;std::vector<S>a;S sx,sr;
 std::string proof_bytes()const{return Ax.bytes()+AR.bytes()+AC.bytes()+sx.bytes()+sr.bytes();}
 std::string payload_bytes()const{auto b=Y.bytes()+R.bytes()+C.bytes();for(const auto& v:a)b+=v.bytes();return b+proof_bytes();}
 std::string bytes()const{std::string b="OAC2";put_u32(b,uint32_t(a.size()));return b+payload_bytes();}
 static CredRequest from_bytes(const Params& p,const std::string& b){Reader r(b);require(r.take(4)=="OAC2","wrong request version");auto n=r.count(p.attrs.size());require(n==p.attrs.size(),"request attribute length");CredRequest x;x.Y=r.point();x.R=r.point();x.C=r.point();for(size_t i=0;i<n;++i)x.a.push_back(r.scalar());x.Ax=r.point();x.AR=r.point();x.AC=r.point();x.sx=r.scalar();x.sr=r.scalar();r.done();return x;}
};
inline S cred_challenge(const Params& p,const CredRequest& r){Hash h("otac/revised/v2/cred");h.blob(p.id);h.point(r.Y);h.point(r.R);h.u32(uint32_t(r.a.size()));for(const auto& a:r.a)h.scalar(a);h.point(r.C);h.point(r.Ax);h.point(r.AR);h.point(r.AC);return challenge128(h);}
inline CredRequest cred_gen(const Params& p,const S& x,const std::vector<S>& a,Opening& o){
 require(x!=S()&&a.size()==p.attrs.size(),"credential inputs");o.a=a;o.r=S::random();CredRequest r;r.a=a;r.Y=pow(p.h0,x);r.R=pow(r.Y,o.r);r.C=commitment(p,o);
 S wx=S::random(),wr=S::random();r.Ax=pow(p.h0,wx);r.AR=pow(r.Y,wr);r.AC=pow(p.g,wr);S c=cred_challenge(p,r);r.sx=wx+c*x;r.sr=wr+c*o.r;return r;
}
inline bool cred_verify(const Params& p,const CredRequest& r,const std::vector<S>& verified_attrs){if(r.Y.identity()||r.a.size()!=p.attrs.size()||r.a!=verified_attrs)return false;S c=cred_challenge(p,r);G V=r.C/p.attr_product(r.a);return pow(p.h0,r.sx)==r.Ax*pow(r.Y,c)&&pow(r.Y,r.sr)==r.AR*pow(r.R,c)&&pow(p.g,r.sr)==r.AC*pow(V,c);}
inline Credential issue(const Params& p,const CredRequest& r,const std::vector<S>& verified_attrs){
 // verified_attrs comes from external evidence checking, not an unimplemented ZK claim.
 require(cred_verify(p,r,verified_attrs),"issuance request rejected");return {r.C,sign(p,r.C)};
}
// Confirmed in-process state adapter. It does not simulate consensus or a network.
struct Ledger {
 std::map<std::string,G> attrs;std::set<std::string> spent;mutable std::mutex mutex;
 Ledger()=default;
 Ledger(const Ledger& o){std::lock_guard<std::mutex> l(o.mutex);attrs=o.attrs;spent=o.spent;}
 Ledger& operator=(const Ledger& o){if(this!=&o){std::scoped_lock lock(mutex,o.mutex);attrs=o.attrs;spent=o.spent;}return *this;}
 bool contains(const G& C)const{auto key=C.bytes();std::lock_guard<std::mutex> l(mutex);return attrs.count(key)!=0;}
 bool tag_spent(const G& T)const{auto key=T.bytes();std::lock_guard<std::mutex> l(mutex);return spent.count(key)!=0;}
 bool registered_list(const std::vector<G>& list)const{if(!distinct_list(list))return false;std::lock_guard<std::mutex> l(mutex);for(const auto& C:list)if(!attrs.count(C.bytes()))return false;return true;}
 bool register_issued(const Params& p,const Credential& c){if(!sig_verify(p,c.C,c.signature))return false;auto key=c.C.bytes();std::lock_guard<std::mutex> l(mutex);return attrs.emplace(key,c.C).second;}
 bool spend(const G& T){auto key=T.bytes();std::lock_guard<std::mutex> l(mutex);return spent.insert(key).second;}
 bool replace(const G& T,const G& C){auto tag=T.bytes(),key=C.bytes();std::lock_guard<std::mutex> l(mutex);if(spent.count(tag)||attrs.count(key))return false;attrs.emplace(key,C);spent.insert(tag);return true;}
};
struct Selection {std::vector<G>list;int index=-1;};
inline Selection sample_candidates(const Ledger& ledger,const G& C,size_t ell){
 require(ell>=2&&ell<=max_candidates,"candidate count");std::vector<G>pool;
 {std::lock_guard<std::mutex> lock(ledger.mutex);require(ledger.attrs.count(C.bytes())&&ell<=ledger.attrs.size(),"unregistered own commitment or short ledger");for(const auto& entry:ledger.attrs)if(entry.second!=C)pool.push_back(entry.second);}
 for(size_t i=0;i<ell-1;++i)std::swap(pool[i],pool[i+random_below(pool.size()-i)]);
 Selection s;s.index=int(random_below(ell));s.list.reserve(ell);size_t decoy=0;for(size_t i=0;i<ell;++i)s.list.push_back(int(i)==s.index?C:pool[decoy++]);return s;
}
struct Pair {G a,b;std::string bytes()const{return a.bytes()+b.bytes();}bool operator==(const Pair& o)const{return a==o.a&&b==o.b;}};
inline Pair operator*(const Pair& a,const Pair& b){return {a.a*b.a,a.b*b.b};}
inline Pair com(const Params& p,const S& m,const S& s){return {p.g_comb.power(m+s),p.k_comb.power(s)};}
inline size_t gk_dimension(size_t ell){require(ell>=2&&ell<=max_candidates,"OoM candidate count");size_t m=1;while((size_t(1)<<m)<ell)++m;return m;}
struct GK {
 std::vector<Pair>L,A,B,D;std::vector<S>f,za,zb;S zd;
 std::string first_bytes()const{std::string b;for(size_t i=0;i<L.size();++i)b+=L[i].bytes()+A[i].bytes()+B[i].bytes()+D[i].bytes();return b;}
 std::string bytes()const{auto b=first_bytes();for(size_t i=0;i<f.size();++i)b+=f[i].bytes()+za[i].bytes()+zb[i].bytes();return b+zd.bytes();}
 static GK read(Reader& r,size_t m){GK z;for(size_t i=0;i<m;++i){z.L.push_back({r.point(),r.point()});z.A.push_back({r.point(),r.point()});z.B.push_back({r.point(),r.point()});z.D.push_back({r.point(),r.point()});}for(size_t i=0;i<m;++i){z.f.push_back(r.scalar());z.za.push_back(r.scalar());z.zb.push_back(r.scalar());}z.zd=r.scalar();return z;}
 bool shape(size_t m)const{return L.size()==m&&A.size()==m&&B.size()==m&&D.size()==m&&f.size()==m&&za.size()==m&&zb.size()==m;}
};
struct GKSecret {std::vector<S>r,a,s,t,rho;std::vector<int>bits;};
inline std::vector<G> padded(const std::vector<G>& list){size_t count=size_t(1)<<gk_dimension(list.size());std::vector<G> out;out.reserve(count);for(size_t i=0;i<count;++i)out.push_back(list[i%list.size()]);return out;}
enum class CandidateDirection { inverse, direct };
inline std::vector<Pair> gk_coefficient_commitments(
    const Params& p, const std::vector<G>& candidates, size_t index, const GKSecret& witness,
    CandidateDirection direction) {
 auto bases = padded(candidates);
 const size_t count = bases.size();
 const size_t dimensions = witness.a.size();

 // A zero bit in the output mask selects the constant coefficient: C_1/C_0.
 // A one bit selects the X coefficient: keep the candidate on the witness side.
 // After all dimensions, bases[mask] aggregates the signed candidates that
 // match the witness on the bits set in mask.
 for (size_t step = 1; step < count; step *= 2) {
  const size_t selected = index & step;
  for (size_t block = 0; block < count; block += 2 * step) {
   for (size_t low = block; low < block + step; ++low) {
    G difference = bases[low + step] / bases[low];
    G matching = bases[low + selected];
    bases[low] = std::move(difference);
    bases[low + step] = std::move(matching);
   }
  }
 }

 // Each nonempty constant mask contributes one exponent to exactly one degree.
 // Transfer contributes C_t^{-p}; integrated consumption contributes C_t^{p}.
 std::vector<S> products(count);
 std::vector<size_t> degrees(count);
 products[0] = S(direction == CandidateDirection::inverse ? -1 : 1);
 degrees[0] = dimensions;
 std::vector<std::vector<G>> coefficient_bases(dimensions);
 std::vector<std::vector<S>> coefficient_exponents(dimensions);
 for (size_t bit = 0, step = 1; bit < dimensions; ++bit, step *= 2) {
  for (size_t mask = 0; mask < step; ++mask) {
   const size_t constants = mask + step;
   const size_t degree = degrees[mask] - 1;
   degrees[constants] = degree;
   products[constants] = products[mask] * witness.a[bit];
   coefficient_bases[degree].push_back(std::move(bases[count - 1 - constants]));
   coefficient_exponents[degree].push_back(products[constants]);
  }
 }
 std::vector<Pair> commitments;
 commitments.reserve(dimensions);
 for (size_t degree = 0; degree < dimensions; ++degree) {
  commitments.push_back({
      oom_windows::product(coefficient_bases[degree], coefficient_exponents[degree]) * p.g_comb.power(witness.rho[degree]),
      p.k_comb.power(witness.rho[degree])});
 }
 return commitments;
}
inline GK gk_first(const Params& p,const std::vector<G>& candidates,int index,GKSecret& w,
                   CandidateDirection direction=CandidateDirection::inverse){
 size_t m=gk_dimension(candidates.size());require(index>=0&&size_t(index)<candidates.size(),"OoM index");GK z;
 for(size_t i=0;i<m;++i){w.bits.push_back((index>>i)&1);w.r.push_back(S::random());w.a.push_back(S::random());w.s.push_back(S::random());w.t.push_back(S::random());w.rho.push_back(S::random());z.L.push_back(com(p,S(w.bits[i]),w.r[i]));z.A.push_back(com(p,w.a[i],w.s[i]));z.B.push_back(com(p,S(w.bits[i])*w.a[i],w.t[i]));}
 // Sum_i p_i(X)=X^m, so every lower coefficient sums to zero.
 // Factor the remaining candidate product by the bits contributing X.
 z.D = gk_coefficient_commitments(p, candidates, size_t(index), w, direction);
 return z;
}
inline S gk_respond(GK& z,const GKSecret& w,const S& opening,const S& c){
 S cp(1),adjust;
 for(size_t k=0;k<w.a.size();++k){
  z.f.push_back(S(w.bits[k])*c+w.a[k]);
  z.za.push_back(w.r[k]*c+w.s[k]);
  z.zb.push_back(w.r[k]*(c-z.f[k])+w.t[k]);
  adjust=adjust+w.rho[k]*cp;
  cp=cp*c;
 }
 z.zd=opening*cp-adjust;
 return cp;
}
inline bool gk_candidate_weights(const Params& p,size_t m,const GK& z,const S& c,
                                 std::vector<S>& weights){
 if (!z.shape(m)) return false;
 const auto challenge_digits = oom_windows::recode(c);
 std::vector<S> complements;
 complements.reserve(m);
 for (size_t k = 0; k < m; ++k) {
  // Both bit checks exponentiate the same L coordinates.
  const oom_windows::OddPowers a(z.L[k].a), b(z.L[k].b);
  const Pair first{oom_windows::power(a, challenge_digits), oom_windows::power(b, challenge_digits)};
  if (!(first * z.A[k] == com(p, z.f[k], z.za[k]))) return false;

  complements.push_back(c - z.f[k]);
  const auto other_digits = oom_windows::recode(complements.back());
  const Pair second{oom_windows::power(a, other_digits), oom_windows::power(b, other_digits)};
  if (!(second * z.B[k] == com(p, S(), z.zb[k]))) return false;
 }

 weights.emplace_back(1);
 for (size_t k = 0; k < m; ++k) {
  const size_t length = weights.size();
  weights.resize(2 * length);
  for (size_t i = 0; i < length; ++i) {
   weights[i + length] = weights[i] * z.f[k];
   weights[i] = weights[i] * complements[k];
  }
 }
 return true;
}

inline bool gk_verify(const Params& p, const std::vector<G>& candidates, const G& D,
                      const G& q2, const GK& z, const S& c) {
 const size_t m = gk_dimension(candidates.size());
 auto first = padded(candidates);
 first.reserve(first.size() + m + 2);
 std::vector<S> e1;
 e1.reserve(first.size() + m + 2);
 if (!gk_candidate_weights(p,m,z,c,e1)) return false;
 // The padded weights sum to c^m. Collect the repeated D before
 // evaluating the membership equations, and use positive exponents.
 std::vector<G> second;
 std::vector<S> e2;
 second.reserve(m + 2);
 e2.reserve(m + 2);
 S cp(1);
 for (size_t k = 0; k < m; ++k) {
  first.push_back(z.D[k].a);
  e1.push_back(cp);
  second.push_back(z.D[k].b);
  e2.push_back(cp);
  cp = cp * c;
 }
 first.push_back(p.g);
 e1.push_back(z.zd);
 first.push_back(inv(D));
 e1.push_back(cp);
 second.push_back(p.k);
 e2.push_back(z.zd);
 second.push_back(inv(q2));
 e2.push_back(cp);
 return oom_windows::product(first, e1).identity() && oom_windows::product(second, e2).identity();
}
inline void bind_list(Hash& h,const std::vector<G>& list){h.u32(uint32_t(list.size()));for(const auto& C:list)h.point(C);}
struct Show {
 static constexpr const char* wire_version="OAS3";
 std::vector<G> list;
 G T;
 GK gk;
 std::vector<S> sa;
 std::string proof_bytes()const{auto b=gk.bytes();for(const auto& s:sa)b+=s.bytes();return b;}
 std::string payload_bytes(bool with_list=true)const{std::string b;if(with_list)for(const auto& C:list)b+=C.bytes();return b+T.bytes()+proof_bytes();}
 std::string bytes(bool with_list=true)const{require(with_list,"self-contained encoding requires candidate list");std::string b=wire_version;put_u32(b,uint32_t(list.size()));put_u32(b,uint32_t(sa.size()));return b+payload_bytes();}
 static Show from_bytes(const Params& p,const std::string& b){
  Reader r(b);
  require(r.take(4)==wire_version,"wrong show version");
  const size_t ell=r.count(max_candidates),hidden=r.count(p.attrs.size()),m=gk_dimension(ell);
  Show s;
  for(size_t i=0;i<ell;++i)s.list.push_back(r.point());
  s.T=r.point();
  s.gk=GK::read(r,m);
  for(size_t i=0;i<hidden;++i)s.sa.push_back(r.scalar());
  r.done();
  require(distinct_list(s.list),"duplicate candidates");
  return s;
 }
};
inline S show_challenge(const Params& p,const Req& req,const Show& s){
 Hash h("otac/revised/v2/sp-int");h.blob(p.id);bind_list(h,s.list);h.point(s.T);
 bind_req(h,req);h.blob(s.gk.first_bytes());return challenge128(h);
}
inline Show show_first(const Params& p,const std::vector<G>& list,int j,const S& opening,
                       const std::vector<int>& hidden,const std::vector<S>& masks,GKSecret& witness){
 Show s;
 s.list=list;
 s.T=p.k_comb.power(opening);
 s.gk=gk_first(p,list,j,witness,CandidateDirection::direct);
 const oom_windows::AttributeProducts attributes(p.attrs);
 s.gk.D.front().a.mul_in(attributes.subset(hidden,masks));
 return s;
}
inline void show_respond(Show& s,const GKSecret& witness,const Opening& opening,
                         const std::vector<int>& hidden,const std::vector<S>& masks,const S& c){
 const S leading=gk_respond(s.gk,witness,opening.r,c);
 for(size_t i=0;i<hidden.size();++i)s.sa.push_back(leading*opening.a[hidden[i]]-masks[i]);
}
inline Show prove(const Params& p,const std::vector<G>& list,int j,const Opening& o,const Req& req){
 require(distinct_list(list)&&j>=0&&size_t(j)<list.size(),"bad candidates");require(valid_request(p,req)&&o.a.size()==p.attrs.size(),"bad attributes");
 for(size_t i=0;i<req.indices.size();++i)require(o.a[req.indices[i]]==req.values[i],"unsatisfied attribute");
 const auto hidden=hidden_indices(int(p.attrs.size()),req);
 std::vector<S> masks;
 for(size_t i=0;i<hidden.size();++i)masks.push_back(S::random());
 GKSecret witness;
 auto s=show_first(p,list,j,o.r,hidden,masks,witness);
 const S c=show_challenge(p,req,s);
 show_respond(s,witness,o,hidden,masks,c);
 return s;
}
inline Show proof_gen(const Params& p,const Ledger& ledger,const G& C,const Opening& o,size_t ell,const Req& req){auto selection=sample_candidates(ledger,C,ell);return prove(p,selection.list,selection.index,o,req);}
inline G spend_verification_product(const std::vector<G>& bases, const std::vector<S>& exponents,
                                    size_t padded_candidates) {
 constexpr size_t candidate_limit = 64;
 constexpr size_t attribute_limit = 64;
 constexpr size_t interleaved_limit = candidate_limit + 6 + 2 + attribute_limit;
 if (bases.size() <= oom_windows::max_interleaved_terms ||
     padded_candidates > candidate_limit || bases.size() > interleaved_limit) {
  return oom_windows::product(bases, exponents);
 }

 // Keep the candidate and attribute terms in a single interleaved product.
 require(bases.size() == exponents.size(), "Spend verification product length mismatch");
 std::vector<oom_windows::OddPowers> powers;
 powers.reserve(bases.size());
 return oom_windows::interleave(exponents, [&](size_t i) -> const oom_windows::OddPowers* {
  if (bases[i].identity()) return nullptr;
  return &powers.emplace_back(bases[i]);
 });
}
inline bool verify_show_transcript(const Params& p,const Req& req,const Show& s,
                                  const std::vector<int>& hidden,const S& c){
 const size_t m=gk_dimension(s.list.size());
 auto first=padded(s.list);
 const size_t padded_candidates = first.size();
 first.reserve(first.size()+m+2+hidden.size());
 std::vector<S> e1;
 e1.reserve(first.capacity());
 if(!gk_candidate_weights(p,m,s.gk,c,e1))return false;

 std::vector<G> second;
 std::vector<S> e2;
 second.reserve(m+2);
 e2.reserve(m+2);
 S cp(1);
 for(size_t b=0;b<m;++b){
  first.push_back(inv(s.gk.D[b].a));
  e1.push_back(cp);
  second.push_back(inv(s.gk.D[b].b));
  e2.push_back(cp);
  cp=cp*c;
 }
 // The weights of all padded candidates sum to c^m.
 first.push_back(inv(public_product(p,req)));
 e1.push_back(cp);
 second.push_back(s.T);
 e2.push_back(cp);
 first.push_back(inv(p.g));
 e1.push_back(s.gk.zd);
 second.push_back(inv(p.k));
 e2.push_back(s.gk.zd);
 for(size_t i=0;i<hidden.size();++i){
  first.push_back(inv(p.attrs[hidden[i]]));
  e1.push_back(s.sa[i]);
 }
 return spend_verification_product(first,e1,padded_candidates).identity()
     && oom_windows::product(second,e2).identity();
}
inline bool verify_proof(const Params& p,const Req& req,const Show& s){
 if(!valid_request(p,req)||!distinct_list(s.list))return false;
 size_t m=gk_dimension(s.list.size());if(!s.gk.shape(m))return false;
 auto hidden=hidden_indices(int(p.attrs.size()),req);if(s.sa.size()!=hidden.size())return false;
 return verify_show_transcript(p,req,s,hidden,show_challenge(p,req,s));
}
inline bool verify(const Params& p,Ledger& ledger,const Req& req,const Show& s){if(!ledger.registered_list(s.list)||!verify_proof(p,req,s))return false;return ledger.spend(s.T);}
struct TransferProof {
 std::vector<G>list;G T,C,D,U,A,B,AB;GK gk;S sr,sB;std::vector<S>sa;
 // D,U are in pi_tr in section 6.2.3; T,C are top-level public output.
 std::string proof_bytes()const{auto b=D.bytes()+U.bytes()+gk.bytes()+A.bytes()+B.bytes()+AB.bytes()+sr.bytes()+sB.bytes();for(const auto& s:sa)b+=s.bytes();return b;}
 std::string payload_bytes(bool with_list=true)const{std::string b;if(with_list)for(const auto& C0:list)b+=C0.bytes();return b+T.bytes()+C.bytes()+proof_bytes();}
 std::string bytes()const{std::string b="OAT2";put_u32(b,uint32_t(list.size()));put_u32(b,uint32_t(sa.size()));return b+payload_bytes();}
 static TransferProof from_bytes(const Params& p,const std::string& b){Reader r(b);require(r.take(4)=="OAT2","wrong transfer version");size_t ell=r.count(max_candidates),n=r.count(p.attrs.size()),m=gk_dimension(ell);require(n==p.attrs.size(),"transfer attribute length");TransferProof t;for(size_t i=0;i<ell;++i)t.list.push_back(r.point());t.T=r.point();t.C=r.point();t.D=r.point();t.U=r.point();t.gk=GK::read(r,m);t.A=r.point();t.B=r.point();t.AB=r.point();t.sr=r.scalar();t.sB=r.scalar();for(size_t i=0;i<n;++i)t.sa.push_back(r.scalar());r.done();require(distinct_list(t.list),"duplicate transfer candidates");return t;}
};
inline S transfer_challenge(const Params& p,const TransferProof& t){Hash h("otac/revised/v2/tr");h.blob(p.id);bind_list(h,t.list);h.point(t.T);h.point(t.C);h.point(t.D);h.point(t.U);h.blob(t.gk.first_bytes());h.point(t.A);h.point(t.B);h.point(t.AB);return challenge128(h);}
struct TransferResult {TransferProof proof;G C;Opening opening;};
inline TransferResult transfer(const Params& p,const Ledger& ledger,const std::vector<G>& list,int j,const Opening& old){
 require(j>=0&&size_t(j)<list.size()&&ledger.registered_list(list),"bad transfer list");
 const oom_windows::AttributeProducts attributes(p.attrs);
 G attribute_term=attributes.full(old.a);require(p.g_comb.power(old.r)*attribute_term==list[j],"old transfer opening");TransferResult result;auto& t=result.proof;t.list=list;t.T=p.k_comb.power(old.r);require(!ledger.tag_spent(t.T),"old transfer tag spent");result.opening.a=old.a;
 for(;;){result.opening.r=S::random();result.C=p.g_comb.power(result.opening.r)*attribute_term;if(!ledger.contains(result.C)&&!ledger.tag_spent(p.k_comb.power(result.opening.r)))break;}t.C=result.C;
 S delta=S::random(),rho=old.r+delta;t.D=list[j]*p.g_comb.power(delta);t.U=p.k_comb.power(rho);GKSecret w;t.gk=gk_first(p,list,j,w);
 S wr=S::random(),wB=S::random();std::vector<S>wa;for(size_t i=0;i<p.attrs.size();++i)wa.push_back(S::random());G product=attributes.full(wa);t.A=p.g_comb.power(wr)*product;t.B=p.k_comb.power(wr);t.AB=p.g_comb.power(wB)*product;
 S c=transfer_challenge(p,t);gk_respond(t.gk,w,delta,c);t.sr=wr+c*rho;t.sB=wB+c*result.opening.r;for(size_t i=0;i<old.a.size();++i)t.sa.push_back(wa[i]+c*old.a[i]);return result;
}
inline TransferResult transfer(const Params& p,const Ledger& ledger,const G& C,const Opening& old,size_t ell){auto selection=sample_candidates(ledger,C,ell);return transfer(p,ledger,selection.list,selection.index,old);}
inline bool verify_transfer_proof(const Params& p,const TransferProof& t){if(!distinct_list(t.list)||t.sa.size()!=p.attrs.size()||!t.gk.shape(gk_dimension(t.list.size())))return false;S c=transfer_challenge(p,t);if(!gk_verify(p,t.list,t.D,t.U/t.T,t.gk,c))return false;G product=msm(p.attrs,t.sa);return p.g_comb.power(t.sr)*product==t.A*pow(t.D,c)&&p.k_comb.power(t.sr)==t.B*pow(t.U,c)&&p.g_comb.power(t.sB)*product==t.AB*pow(t.C,c);}
inline bool verify_transfer(const Params& p,Ledger& ledger,const TransferProof& t){if(!ledger.registered_list(t.list)||!verify_transfer_proof(p,t))return false;return ledger.replace(t.T,t.C);}
} // namespace otac::scheme

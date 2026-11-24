#pragma once

namespace curve_ops {

struct FieldValue {
 mutable element_t v;
 explicit FieldValue(field_ptr f){element_init(v,f);element_set0(v);}
 FieldValue(const FieldValue& a){element_init(v,a.v->field);element_set(v,a.v);}
 FieldValue(FieldValue&& a)noexcept{element_init(v,a.v->field);std::swap(v[0],a.v[0]);}
 ~FieldValue(){element_clear(v);}
 FieldValue& operator=(const FieldValue& a){element_set(v,a.v);return *this;}
 FieldValue& operator=(FieldValue&& a)noexcept{std::swap(v[0],a.v[0]);return *this;}
};

struct Workspace {
 std::array<element_t,18> t;
 element_ptr a;
 bool a_zero;
 explicit Workspace(element_ptr group):a(curve_a_coeff(group)),a_zero(element_is0(a)!=0){
  auto f=curve_x_coord(group)->field;
  for(auto& x:t)element_init(x,f);
 }
 ~Workspace(){for(auto& x:t)element_clear(x);}
 Workspace(const Workspace&)=delete;
};

// Short-Weierstrass Jacobian coordinates: x=X/Z^2, y=Y/Z^3.
// Formulas: EFD dbl-2007-bl, add-2007-bl, madd-2007-bl.
struct Point {
 FieldValue x,y,z;
 explicit Point(field_ptr f):x(f),y(f),z(f){}
 bool infinity()const{return element_is0(z.v)!=0;}
 void reset(){element_set0(z.v);}
 void assign(const Point& p){element_set(x.v,p.x.v);element_set(y.v,p.y.v);element_set(z.v,p.z.v);}
 void assign(element_ptr p){
  if(element_is1(p)){reset();return;}
  element_set(x.v,curve_x_coord(p));element_set(y.v,curve_y_coord(p));element_set1(z.v);
 }
 void twice(Workspace& w){
  if(infinity()||element_is0(y.v)){reset();return;}
  auto& t=w.t;
  element_square(t[0],x.v);                         // A
  element_square(t[1],y.v);                         // B
  element_square(t[2],t[1]);                        // C
  element_add(t[3],x.v,t[1]);element_square(t[3],t[3]);
  element_sub(t[3],t[3],t[0]);element_sub(t[3],t[3],t[2]);element_add(t[3],t[3],t[3]); // D
  element_add(t[4],t[0],t[0]);element_add(t[4],t[4],t[0]); // E
  if(!w.a_zero){element_square(t[5],z.v);element_square(t[5],t[5]);element_mul(t[5],t[5],w.a);element_add(t[4],t[4],t[5]);}
  element_square(t[5],t[4]);                        // F
  element_add(t[6],t[3],t[3]);element_sub(t[6],t[5],t[6]); // X3
  element_sub(t[7],t[3],t[6]);element_mul(t[7],t[4],t[7]);
  element_add(t[8],t[2],t[2]);element_add(t[8],t[8],t[8]);element_add(t[8],t[8],t[8]);element_sub(t[7],t[7],t[8]); // Y3
  element_mul(t[8],y.v,z.v);element_add(t[8],t[8],t[8]); // Z3
  element_set(x.v,t[6]);element_set(y.v,t[7]);element_set(z.v,t[8]);
 }
 void add_affine(element_ptr p,Workspace& w){
  if(element_is1(p))return;
  if(infinity()){assign(p);return;}
  auto& t=w.t;
  element_square(t[0],z.v);
  element_mul(t[1],curve_x_coord(p),t[0]);            // U2
  element_mul(t[2],curve_y_coord(p),z.v);element_mul(t[2],t[2],t[0]); // S2
  if(element_cmp(x.v,t[1])==0){if(element_cmp(y.v,t[2])==0)twice(w);else reset();return;}
  element_sub(t[3],t[1],x.v);                       // H
  element_square(t[4],t[3]);                       // HH
  element_add(t[5],t[4],t[4]);element_add(t[5],t[5],t[5]); // I
  element_mul(t[6],t[3],t[5]);                      // J
  element_sub(t[7],t[2],y.v);element_add(t[7],t[7],t[7]); // r
  element_mul(t[8],x.v,t[5]);                       // V
  element_square(t[9],t[7]);element_sub(t[9],t[9],t[6]);element_add(t[10],t[8],t[8]);element_sub(t[9],t[9],t[10]);
  element_sub(t[10],t[8],t[9]);element_mul(t[10],t[7],t[10]);element_mul(t[11],y.v,t[6]);element_add(t[11],t[11],t[11]);element_sub(t[10],t[10],t[11]);
  element_add(t[11],z.v,t[3]);element_square(t[11],t[11]);element_sub(t[11],t[11],t[0]);element_sub(t[11],t[11],t[4]);
  element_set(x.v,t[9]);element_set(y.v,t[10]);element_set(z.v,t[11]);
 }
 void add(const Point& p,Workspace& w){
  if(p.infinity())return;
  if(infinity()){assign(p);return;}
  if(this==&p){twice(w);return;}
  auto& t=w.t;
  element_square(t[0],z.v);element_square(t[1],p.z.v);
  element_mul(t[2],x.v,t[1]);element_mul(t[3],p.x.v,t[0]); // U1,U2
  element_mul(t[4],y.v,p.z.v);element_mul(t[4],t[4],t[1]);
  element_mul(t[5],p.y.v,z.v);element_mul(t[5],t[5],t[0]); // S1,S2
  if(element_cmp(t[2],t[3])==0){if(element_cmp(t[4],t[5])==0)twice(w);else reset();return;}
  element_sub(t[6],t[3],t[2]);                       // H
  element_add(t[7],t[6],t[6]);element_square(t[7],t[7]); // I
  element_mul(t[8],t[6],t[7]);                      // J
  element_sub(t[9],t[5],t[4]);element_add(t[9],t[9],t[9]); // r
  element_mul(t[10],t[2],t[7]);                     // V
  element_square(t[11],t[9]);element_sub(t[11],t[11],t[8]);element_add(t[12],t[10],t[10]);element_sub(t[11],t[11],t[12]);
  element_sub(t[12],t[10],t[11]);element_mul(t[12],t[9],t[12]);element_mul(t[13],t[4],t[8]);element_add(t[13],t[13],t[13]);element_sub(t[12],t[12],t[13]);
  element_add(t[13],z.v,p.z.v);element_square(t[13],t[13]);element_sub(t[13],t[13],t[0]);element_sub(t[13],t[13],t[1]);element_mul(t[13],t[13],t[6]);
  element_set(x.v,t[11]);element_set(y.v,t[12]);element_set(z.v,t[13]);
 }
 void write(element_ptr out,Workspace& w)const{
  if(infinity()){element_set1(out);return;}
  auto& t=w.t;
  element_invert(t[0],z.v);element_square(t[1],t[0]);element_mul(t[2],t[1],t[0]);
  curve_set_si(out,0,0);
  element_mul(curve_x_coord(out),x.v,t[1]);element_mul(curve_y_coord(out),y.v,t[2]);
 }
};

inline void power(element_ptr out,element_ptr base,mpz_t scalar){
 if(mpz_sgn(scalar)==0||element_is1(base)){element_set1(out);return;}
 Workspace w(base);Point acc(curve_x_coord(base)->field);
 for(int i=int(mpz_sizeinbase(scalar,2))-1;i>=0;--i){acc.twice(w);if(mpz_tstbit(scalar,i))acc.add_affine(base,w);}
 acc.write(out,w);
}

inline void multiexp(element_ptr out,const std::vector<element_ptr>& bases,const std::vector<mpz_ptr>& scalars){
 if(bases.empty()){element_set1(out);return;}
 require(bases.size()==scalars.size(),"MSM length mismatch");
 Workspace workspace(bases[0]);auto field=curve_x_coord(bases[0])->field;
 size_t bits=0;for(auto s:scalars)bits=std::max(bits,mpz_sgn(s)?mpz_sizeinbase(s,2):size_t(0));
 if(bits==0){element_set1(out);return;}
 unsigned width=bases.size()<8?2:bases.size()<32?3:bases.size()<128?4:bases.size()<512?5:6;
 std::vector<Point> buckets;buckets.reserve(size_t(1)<<width);
 for(unsigned i=0;i<(1u<<width);++i)buckets.emplace_back(field);
 Point result(field),running(field);
 for(int pos=int((bits-1)/width)*int(width);pos>=0;pos-=int(width)){
  if(pos!=int((bits-1)/width)*int(width))for(unsigned j=0;j<width;++j)result.twice(workspace);
  for(auto& p:buckets)p.reset();
  for(size_t i=0;i<bases.size();++i){unsigned digit=0;for(unsigned j=0;j<width;++j)digit|=unsigned(mpz_tstbit(scalars[i],pos+j))<<j;if(digit)buckets[digit].add_affine(bases[i],workspace);}
  running.reset();
  for(unsigned digit=(1u<<width)-1;digit>0;--digit){running.add(buckets[digit],workspace);result.add(running,workspace);}
 }
 result.write(out,workspace);
}

struct FixedBase {
 element_pp_t table;
 explicit FixedBase(element_ptr base){element_pp_init(table,base);}
 ~FixedBase(){element_pp_clear(table);}
 FixedBase(const FixedBase&)=delete;
};

} // namespace curve_ops

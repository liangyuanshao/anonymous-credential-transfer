#pragma once
#include "../src/ours.hpp"

namespace otac::scheme {
// Functional/adversarial regression checks; these are not security proofs.
inline int run_tests(){
 int checks=0;
 auto check=[&](bool ok,const std::string& name){++checks;require(ok,"protocol check failed: "+name);};
 auto rejects=[&](const std::function<void()>& f,const std::string& name){bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}check(rejected,name);};
 PP base(4);Params p(base);Ledger initial;S x=S::random(true);std::vector<S>a={S(11),S(22),S(33),S(44)};Opening o;
 auto application=cred_gen(p,x,a,o);auto credential=issue(p,application,a);auto req=request(a,2);
 check(application.Y==pow(p.h0,x),"public key");check(application.R==pow(application.Y,o.r),"R uses r");check(application.C==commitment(p,o),"credential commitment");
 check(cred_verify(p,application,a),"credential request");check(sig_verify(p,credential.C,credential.signature),"signature");
 check(initial.register_issued(p,credential),"confirmed issuance");check(!initial.register_issued(p,credential),"duplicate issuance");check(initial.attrs.size()==1,"single registered record");
 auto decoded=CredRequest::from_bytes(p,application.bytes());check(decoded.bytes()==application.bytes()&&cred_verify(p,decoded,a),"request codec roundtrip");
 auto dc=Credential::from_bytes(credential.bytes());check(dc.bytes()==credential.bytes()&&sig_verify(p,dc.C,dc.signature),"credential codec roundtrip");
 auto ds=Sig::from_bytes(credential.signature.bytes());check(ds.bytes()==credential.signature.bytes(),"signature codec roundtrip");
 for(int which=0;which<8;++which){auto bad=application;
  if(which==0)bad.Y=bad.Y*p.g;
  if(which==1)bad.R=bad.R*p.g;
  if(which==2)bad.C=bad.C*p.g;
  if(which==3)bad.Ax=bad.Ax*p.g;
  if(which==4)bad.AR=bad.AR*p.g;
  if(which==5)bad.AC=bad.AC*p.g;
  if(which==6)bad.sx=bad.sx+S(1);
  if(which==7)bad.sr=bad.sr+S(1);
  check(!cred_verify(p,bad,a),"tampered request field "+std::to_string(which));
 }
 {auto bad=application;bad.a[0]=bad.a[0]+S(1);check(!cred_verify(p,bad,bad.a),"changed certified attribute");bad=application;bad.Y=G();check(!cred_verify(p,bad,a),"identity public key");}
 {auto wrong=a;wrong[0]=S(55);check(!cred_verify(p,application,wrong),"evidence attribute mismatch");rejects([&]{issue(p,application,wrong);},"issuer rejects evidence mismatch");}
 {auto bad=credential;bad.signature.z=bad.signature.z+S(1);check(!initial.register_issued(p,bad),"registration verifies signature");}
 check(mpz_sizeinbase(cred_challenge(p,application).v,2)<=challenge_bits,"128-bit credential challenge");
 // Genuine decoys: each is requested, verified, signed, and registered before use.
 for(int i=0;i<6;++i){Opening decoy;auto r=cred_gen(p,S::random(true),a,decoy);auto c=issue(p,r,a);check(initial.register_issued(p,c),"decoy issuance "+std::to_string(i));}
 rejects([&]{sample_candidates(initial,G::hash("not-registered"),3);},"own commitment unregistered");
 rejects([&]{sample_candidates(initial,credential.C,1);},"candidate size below two");
 rejects([&]{sample_candidates(initial,credential.C,8);},"candidate size exceeds ledger");
 for(size_t ell:{size_t(2),size_t(3),size_t(5),size_t(7)}){
  auto selected=sample_candidates(initial,credential.C,ell);check(selected.list.size()==ell&&selected.list[selected.index]==credential.C&&distinct_list(selected.list),"candidate selection "+std::to_string(ell));
  auto show=prove(p,selected.list,selected.index,o,req);check(verify_proof(p,req,show),"OoM completeness ell "+std::to_string(ell));
  check(show.T==pow(p.k,o.r),"fixed tag ell "+std::to_string(ell));
  auto parsed=Show::from_bytes(p,show.bytes());check(parsed.bytes()==show.bytes()&&verify_proof(p,req,parsed),"show codec ell "+std::to_string(ell));
  Ledger ledger=initial;check(verify(p,ledger,req,parsed),"consume ell "+std::to_string(ell));check(!verify(p,ledger,req,parsed),"replay rejected ell "+std::to_string(ell));
  auto second=prove(p,selected.list,selected.index,o,req);
  check(second.T==show.T&&second.gk.first_bytes()!=show.gk.first_bytes(),"fresh proof same tag ell "+std::to_string(ell));
  check(verify_proof(p,req,second)&&!verify(p,ledger,req,second),"fresh proof cannot be respent ell "+std::to_string(ell));
 }
 auto show=proof_gen(p,initial,credential.C,o,3,req);check(mpz_sizeinbase(show_challenge(p,req,show).v,2)<=challenge_bits,"128-bit show challenge");
 for(int which=0;which<9;++which){auto bad=show;
  if(which==0)bad.T=bad.T*p.g;
  if(which==1)bad.sa[0]=bad.sa[0]+S(1);
  if(which==2)bad.gk.L[0].a=bad.gk.L[0].a*p.g;
  if(which==3)bad.gk.A[0].b=bad.gk.A[0].b*p.g;
  if(which==4)bad.gk.B[0].a=bad.gk.B[0].a*p.g;
  if(which==5)bad.gk.D[0].a=bad.gk.D[0].a*p.g;
  if(which==6)bad.gk.D[0].b=bad.gk.D[0].b*p.g;
  if(which==7)bad.gk.D[1].a=bad.gk.D[1].a*p.g;
  if(which==8)bad.gk.zd=bad.gk.zd+S(1);
  check(!verify_proof(p,req,bad),"tampered show field "+std::to_string(which));
 }
 for(int which=0;which<3;++which){auto bad=show;if(which==0)bad.gk.f[0]=bad.gk.f[0]+S(1);if(which==1)bad.gk.za[0]=bad.gk.za[0]+S(1);if(which==2)bad.gk.zb[0]=bad.gk.zb[0]+S(1);check(!verify_proof(p,req,bad),"tampered GK response "+std::to_string(which));}
 {auto bad=show;bad.list[0]=bad.list[1];check(!verify_proof(p,req,bad),"duplicate actual candidates");bad=show;bad.gk.L.pop_back();check(!verify_proof(p,req,bad),"malformed GK vector");bad=show;bad.sa.pop_back();check(!verify_proof(p,req,bad),"missing attribute response");}
 {auto changed=req;changed.values[0]=changed.values[0]+S(1);check(!verify_proof(p,changed,show),"changed service requirement");rejects([&]{proof_gen(p,initial,credential.C,o,3,changed);},"unsatisfied requirement generation");}
 {auto badreq=req;badreq.indices[1]=badreq.indices[0];check(!verify_proof(p,badreq,show),"duplicate requested index");badreq=req;badreq.values.pop_back();check(!verify_proof(p,badreq,show),"request shape");badreq=req;badreq.indices[0]=-1;check(!verify_proof(p,badreq,show),"negative request index");}
 {
  for(bool change_randomness:{true,false}){
   auto wrong=o;
   if(change_randomness)wrong.r=wrong.r+S(1);
   else {
    const auto hidden=hidden_indices(int(o.a.size()),req);
    wrong.a[hidden.front()]=wrong.a[hidden.front()]+S(1);
   }
   const auto invalid=proof_gen(p,initial,credential.C,wrong,3,req);
   auto state=initial;
   check(!verify(p,state,req,invalid),change_randomness?"wrong opening randomness rejected":"wrong hidden attribute rejected");
   check(state.spent.empty(),"wrong opening does not spend a tag");
  }
 }
 {Ledger missing=initial;missing.attrs.erase(show.list[0].bytes());check(!verify(p,missing,req,show),"unregistered candidate rejected");check(missing.spent.empty(),"failed proof leaves state unchanged");}
 for(int disclose:{0,4}){auto r=request(a,disclose);auto s=proof_gen(p,initial,credential.C,o,3,r);check(verify_proof(p,r,s),"zero/all disclosed "+std::to_string(disclose));}
 {
  const auto selected=sample_candidates(initial,credential.C,5);
  const auto hidden=hidden_indices(int(o.a.size()),req);
  std::vector<S> masks;
  for(size_t i=0;i<hidden.size();++i)masks.push_back(S::random());
  GKSecret witness;
  const auto first=show_first(p,selected.list,selected.index,o.r,hidden,masks,witness);
  const auto m=gk_dimension(selected.list.size());
  std::vector<Show> transcripts;
  for(size_t e=0;e<=m;++e){
   auto response=first;
   const S c(static_cast<long>(e));
   show_respond(response,witness,o,hidden,masks,c);
   check(verify_show_transcript(p,req,response,hidden,c),"same first message, distinct challenge");
   transcripts.push_back(std::move(response));
  }
  size_t index=0;
  for(size_t i=0;i<m;++i){
   const S bit=transcripts[1].gk.f[i]-transcripts[0].gk.f[i];
   check(bit==S()||bit==S(1),"extracted index bit");
   if(bit==S(1))index|=size_t(1)<<i;
  }
  S extracted_opening;
  std::vector<S> extracted_attributes(hidden.size());
  for(size_t e=0;e<=m;++e){
   S denominator(1);
   for(size_t other=0;other<=m;++other)
    if(e!=other)denominator=denominator*S(static_cast<long>(e)-static_cast<long>(other));
   const S weight=denominator.inv();
   extracted_opening=extracted_opening+weight*transcripts[e].gk.zd;
   for(size_t i=0;i<hidden.size();++i)
    extracted_attributes[i]=extracted_attributes[i]+weight*transcripts[e].sa[i];
  }
  check(index==size_t(selected.index)&&extracted_opening==o.r,"extracted source and opening");
  for(size_t i=0;i<hidden.size();++i)
   check(extracted_attributes[i]==o.a[hidden[i]],"extracted hidden attribute");
 }
 auto tr=transfer(p,initial,credential.C,o,3);check(tr.C==commitment(p,tr.opening)&&tr.opening.a==a,"transfer same attributes new opening");check(tr.proof.T==pow(p.k,o.r),"transfer old tag");
 check(verify_transfer_proof(p,tr.proof),"transfer proof");check(mpz_sizeinbase(transfer_challenge(p,tr.proof).v,2)<=challenge_bits,"128-bit transfer challenge");
 auto ptr=TransferProof::from_bytes(p,tr.proof.bytes());check(ptr.bytes()==tr.proof.bytes()&&verify_transfer_proof(p,ptr),"transfer codec roundtrip");
 check(tr.proof.payload_bytes().find(pow(p.k,tr.opening.r).bytes())==std::string::npos,"new tag absent from public output");
 for(int which=0;which<11;++which){auto bad=tr.proof;
  if(which==0)bad.T=bad.T*p.g;
  if(which==1)bad.C=bad.C*p.g;
  if(which==2)bad.D=bad.D*p.g;
  if(which==3)bad.U=bad.U*p.g;
  if(which==4)bad.A=bad.A*p.g;
  if(which==5)bad.B=bad.B*p.g;
  if(which==6)bad.AB=bad.AB*p.g;
  if(which==7)bad.sr=bad.sr+S(1);
  if(which==8)bad.sB=bad.sB+S(1);
  if(which==9)bad.sa[0]=bad.sa[0]+S(1);
  if(which==10)bad.gk.zd=bad.gk.zd+S(1);
  check(!verify_transfer_proof(p,bad),"tampered transfer field "+std::to_string(which));
 }
 {auto bad=tr.proof;bad.sa.pop_back();check(!verify_transfer_proof(p,bad),"missing shared attribute response");bad=tr.proof;bad.list[0]=bad.list[1];check(!verify_transfer_proof(p,bad),"duplicate transfer candidates");}
 // Competing operations are prepared against one snapshot; one atomic commit wins.
 auto competing=transfer(p,initial,credential.C,o,3);Ledger state=initial;size_t old_records=state.attrs.size();
 check(verify_transfer(p,state,tr.proof),"confirmed transfer");check(state.attrs.size()==old_records+1&&state.spent.size()==1,"transfer state delta");check(!verify_transfer(p,state,tr.proof),"transfer replay");check(!verify_transfer(p,state,competing.proof),"conflicting transfer rejected");
 check(!verify(p,state,req,show),"old spend after transfer rejected");auto old_again=proof_gen(p,state,credential.C,o,3,req);check(!verify(p,state,req,old_again),"old rederived proof after transfer rejected");rejects([&]{transfer(p,state,credential.C,o,3);},"old owner cannot retransfer");
 auto tr2=transfer(p,state,tr.C,tr.opening,3);check(verify_transfer(p,state,tr2.proof),"second transfer");auto new_show=proof_gen(p,state,tr2.C,tr2.opening,3,req);check(verify(p,state,req,new_show),"consume after two transfers");check(!verify(p,state,req,new_show),"final consume replay");rejects([&]{transfer(p,state,tr2.C,tr2.opening,3);},"consumed unit cannot transfer");
 {Ledger reverse=initial;check(verify(p,reverse,req,show),"consume wins competing order");check(!verify_transfer(p,reverse,tr.proof),"transfer fails after consumption");}
 {Ledger l=initial;G tag=G::hash("ledger-test-tag");check(!l.replace(tag,credential.C),"existing new record rejected");check(!l.tag_spent(tag),"rejected replacement leaves old tag live");}
 // Fixed cryptographic payload and explicit framing remain separately observable.
 size_t BG=p.g.bytes().size(),BQ=size_t(scalar_bytes),m=gk_dimension(3),u=2;
 check(application.proof_bytes().size()==3*BG+2*BQ,"credential proof size");check(application.payload_bytes().size()==6*BG+6*BQ,"request payload size");check(application.bytes().size()==application.payload_bytes().size()+8,"request framing");
 check(show.proof_bytes().size()==8*m*BG+(3*m+u+1)*BQ,"consume proof size");check(show.payload_bytes().size()==(3+8*m+1)*BG+(3*m+u+1)*BQ,"consume payload size");check(show.bytes().size()==show.payload_bytes().size()+12,"show framing");
 check(tr.proof.proof_bytes().size()==(8*m+5)*BG+(3*m+4+3)*BQ,"transfer proof size");check(tr.proof.payload_bytes().size()==(3+8*m+7)*BG+(3*m+4+3)*BQ,"transfer payload size");check(tr.proof.bytes().size()==tr.proof.payload_bytes().size()+12,"transfer framing");
 rejects([&]{CredRequest::from_bytes(p,application.bytes()+"x");},"trailing request byte");rejects([&]{Show::from_bytes(p,show.bytes().substr(0,show.bytes().size()-1));},"truncated show");rejects([&]{TransferProof::from_bytes(p,tr.proof.bytes()+"x");},"trailing transfer byte");
 {auto old=show.bytes();old.replace(0,4,"OAS2");rejects([&]{Show::from_bytes(p,old);},"old show version rejected");}
 {auto bad=application.bytes();bad.replace(bad.size()-scalar_bytes,scalar_bytes,std::string(size_t(scalar_bytes),char(0xff)));rejects([&]{CredRequest::from_bytes(p,bad);},"noncanonical scalar decode");}
#ifdef OTAC_USE_P256
 {auto bad=application.bytes();bad[8]=char(4);rejects([&]{CredRequest::from_bytes(p,bad);},"bad group tag decode");}
 {auto bad=application.bytes();bad[8]=char(2);bad.replace(9,BG-1,std::string(BG-1,char(0xff)));rejects([&]{CredRequest::from_bytes(p,bad);},"coordinate outside base field");}
 {auto bad=application.bytes();bad.replace(8,BG,std::string(1,'\0')+std::string(BG-1,'\1'));rejects([&]{CredRequest::from_bytes(p,bad);},"noncanonical infinity");}
#else
 {auto bad=application.bytes();bad[8]=char(2);rejects([&]{CredRequest::from_bytes(p,bad);},"bad group tag decode");}
 {auto bad=application.bytes();bad[8+BG-1]=char(2);rejects([&]{CredRequest::from_bytes(p,bad);},"noncanonical point sign");}
 {auto bad=application.bytes();bad.replace(9,BG-2,std::string(BG-2,char(0xff)));rejects([&]{CredRequest::from_bytes(p,bad);},"coordinate outside base field");}
 {
  G scratch;auto coord=curve_x_coord(scratch.v);element_t rhs;element_init(rhs,coord->field);
  bool found=false;
  for(int i=0;i<1000;++i){element_set_si(coord,i);element_square(rhs,coord);element_add(rhs,rhs,curve_a_coeff(scratch.v));element_mul(rhs,rhs,coord);element_add(rhs,rhs,curve_b_coeff(scratch.v));if(!element_is_sqr(rhs)){found=true;break;}}
  check(found,"noncurve coordinate fixture");std::string encoded(BG,char(0));encoded[0]=1;element_to_bytes(reinterpret_cast<unsigned char*>(encoded.data()+1),coord);element_clear(rhs);
  auto bad=application.bytes();bad.replace(8,BG,encoded);rejects([&]{CredRequest::from_bytes(p,bad);},"noncurve compressed coordinate");
 }
#endif
 std::cout<<"{\"suite\":\"credential-protocol\",\"checks\":"<<checks<<",\"passed\":true,\"challenge_bits\":"<<challenge_bits<<"}\n";return checks;
}
} // namespace otac::scheme

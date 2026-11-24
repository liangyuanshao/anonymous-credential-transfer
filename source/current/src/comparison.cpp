#include "ours.hpp"
#include "benchmark_defaults.hpp"
#include "../baselines/acl/acl.hpp"
#include "../baselines/protocol_checks.hpp"
#include <filesystem>
#include <optional>
using namespace otac;
namespace scheme=otac::scheme;
struct Writer {
 std::ofstream raw,sizes;
 std::string directory;
 std::string exp;int ell,n,d;
 Writer(const std::string&out):raw(out+"/raw_timings.csv"),sizes(out+"/communication.csv"),directory(out){
  require(bool(raw)&&bool(sizes),"cannot write experiment files");
  raw<<"experiment,scheme,profile,operation,ell,n,d,repetition,ms,bytes,operation_complete\n";
  sizes<<"experiment,scheme,ell,n,d,quantity,bytes,operation_complete,basis\n";
 }
 void emit(int rep,const std::string&scheme,const std::string&op,double ms,size_t bytes,bool complete=true,const std::string&profile="pbc-native"){
  if(rep<0)return;
  raw<<exp<<','<<scheme<<','<<profile<<','<<op<<','<<ell<<','<<n<<','<<d<<','<<rep<<','<<std::setprecision(12)<<ms<<','<<bytes<<','<<int(complete)<<'\n';raw.flush();
 }
 void size(const std::string&scheme,const std::string&q,size_t bytes,bool complete,const std::string&basis){
  sizes<<exp<<','<<scheme<<','<<ell<<','<<n<<','<<d<<','<<q<<','<<bytes<<','<<int(complete)<<','<<basis<<'\n';sizes.flush();
 }
 void parameter_setup(const std::string&component,double ms){
  std::ofstream f(directory+"/setup.csv",std::ios::app);f<<component<<"_n"<<n<<",0,"<<std::setprecision(12)<<ms<<'\n';
 }
};
static void baseline_case(Writer&w,int rep,const PP&p,const std::vector<S>&attrs,const Req&req,const uprove::Params&up,const S&holder_key,const cy22::Paillier* he,const std::optional<cy22::Params>& cy_params){
 Opening o;o.x=holder_key;o.a=attrs;bool ok=false;double holder,issuer,ms;std::set<std::string>spent;
 acl::Registration ar;acl::IssuerState ai;acl::UserState au;acl::Reply reply;acl::Token at;
 holder=timed([&]{o.r=S::random();ar=acl::register_user(p,o);});issuer=timed([&]{ai=acl::issuer_prepare(p,ar,attrs);});
 holder+=timed([&]{au=acl::user_prepare(p,ar,ai);});issuer+=timed([&]{reply=acl::issuer_reply(p,ai,au);});
 holder+=timed([&]{at=acl::user_finish(au,reply);require(acl::token_verify(p,at),"ACL issuance validation");});
 w.emit(rep,"ACL","holder_issue",holder,ar.bytes(o).size());w.emit(rep,"ACL","issuer_issue",issuer,at.bytes().size());
 acl::Presentation ap;ms=timed([&]{ap=acl::present(p,at,o,au,ai,req);});w.emit(rep,"ACL","show",ms,ap.bytes().size());
 ms=timed([&]{ok=acl::verify(p,req,ap,spent);});require(ok,"ACL presentation");w.emit(rep,"ACL","verify",ms,0);
 uprove::IssuerState ui;uprove::UserState uu;S ur;uprove::Credential uc;
 issuer=timed([&]{ui=uprove::issuer_first(up,attrs);});holder=timed([&]{uu=uprove::user_second(up,attrs,ui.msg);});
 issuer+=timed([&]{ur=uprove::issuer_third(up,ui,uu.challenge);});holder+=timed([&]{uc=uprove::user_finish(up,uu,ur);});
 w.emit(rep,"UPROVE","holder_issue",holder,scalar_bytes,true,"pbc-algebraic");w.emit(rep,"UPROVE","issuer_issue",issuer,ui.msg.bytes().size()+ur.bytes().size(),true,"pbc-algebraic");
 const std::string context="one-token-session/"+std::to_string(w.n)+"/"+std::to_string(rep);
 uprove::Presentation us;ms=timed([&]{us=uprove::present(up,uc,attrs,req,context);});w.emit(rep,"UPROVE","show",ms,us.bytes().size(),true,"pbc-algebraic");
 spent.clear();ms=timed([&]{ok=uprove::verify(up,req,us,context,spent);});require(ok,"U-Prove presentation");w.emit(rep,"UPROVE","verify",ms,0,true,"pbc-algebraic");
 if(rep==0){
  w.size("ACL","issuance_total",ar.bytes(o).size()+3*p.g.bytes().size()+7*scalar_bytes,true,"first issuance with registration");
  w.size("ACL","credential",at.bytes().size(),true,"public credential");w.size("ACL","presentation",ap.bytes().size(),true,"token plus attribute proof");
  w.size("UPROVE","issuance_total",attrs.size()*scalar_bytes+ui.msg.bytes().size()+2*scalar_bytes,true,"attribute submission plus three issuance messages");
  w.size("UPROVE","credential",uc.token.bytes().size(),true,"public token excludes secret key");w.size("UPROVE","presentation",us.bytes().size(),true,"token and subset proof");
 }
 if(!he)return;
 const auto& cy=*cy_params;
 cy22::HolderState ch;cy22::IssuerState ci;cy22::Partial cp;cy22::Credential cc;
 holder=timed([&]{ch=cy22::user_request(cy,attrs);});issuer=timed([&]{ci=cy22::issuer_first_core(cy,*he,ch.req,attrs);});
 holder+=timed([&]{cy22::user_mta_core(*he,ci,ch);});issuer+=timed([&]{cp=cy22::issuer_finish_core(cy,*he,ci,ch.req,ch);});
 holder+=timed([&]{cc=cy22::user_finish(cy,ch,cp,attrs);});
 w.emit(rep,"CY22","holder_issue",holder,ch.req.bytes().size(),false,"honest-party-core");w.emit(rep,"CY22","issuer_issue",issuer,cp.bytes().size(),false,"honest-party-core");
 cy22::Presentation cs;ms=timed([&]{cs=cy22::present(cy,cc,req);});w.emit(rep,"CY22","show",ms,cs.bytes().size(),true,"and-equations");
 spent.clear();ms=timed([&]{ok=cy22::verify(cy,req,cs,spent);});require(ok,"Chan-Yuen AND presentation");w.emit(rep,"CY22","verify",ms,0,true,"and-equations");
 if(rep==0){
  std::string core=ch.req.bytes()+ci.zu1.bytes(2*he->nbytes)+ci.zx.bytes(2*he->nbytes)+ch.z1.bytes(2*he->nbytes)+ch.omega2.bytes()+cp.bytes();
  w.size("CY22","issuance_core_lower_bound",attrs.size()*scalar_bytes+core.size(),false,"excludes unspecified pi_U and HE proofs");
  w.size("CY22","credential",cc.bytes().size(),true,"C and CL signature");w.size("CY22","presentation",cs.bytes().size(),true,"AND witness and credential");
 }
}
static void run_case(Writer&w,int reps,const cy22::Paillier* he){
 auto setup_start=std::chrono::steady_clock::now();
 PP common(w.n);scheme::Params p(common);
 auto elapsed=[&]{auto end=std::chrono::steady_clock::now();double ms=std::chrono::duration<double,std::milli>(end-setup_start).count();setup_start=end;return ms;};
 double common_setup=elapsed();uprove::Params up(common);double up_setup=elapsed();
 std::optional<cy22::Params> cy;
 double cy_setup=0;
 if(he){cy.emplace(common);cy_setup=elapsed();}
 w.parameter_setup("shared_and_credential_parameters",common_setup);w.parameter_setup("uprove_parameters",up_setup);
 if(cy)w.parameter_setup("cy22_parameters",cy_setup);
 const auto attrs=baseline_checks::attributes(w.n);const auto req=request(attrs,w.d);const S x=S::random(true);
 scheme::Ledger pool;
 // Every synthetic decoy is an actually issued and registered commitment.
 // Its private opening is discarded; no other candidate openings reach OoM.
 for(int i=0;i<w.ell-1;i++){
  scheme::Opening decoy;auto request=scheme::cred_gen(p,S::random(true),attrs,decoy);
  auto cred=scheme::issue(p,request,attrs);require(pool.register_issued(p,cred),"decoy registration");
 }
 for(int rep=-3;rep<reps;rep++){
  scheme::Opening o;scheme::CredRequest request;scheme::Credential cred;
  double ms=timed([&]{request=scheme::cred_gen(p,x,attrs,o);});w.emit(rep,"OTAC","holder_issue",ms,request.payload_bytes().size());
  ms=timed([&]{cred=scheme::issue(p,request,attrs);});w.emit(rep,"OTAC","issuer_issue",ms,cred.bytes().size());
  scheme::Ledger ledger=pool;require(ledger.register_issued(p,cred),"credential registration");
  scheme::Show show;ms=timed([&]{auto selection=scheme::sample_candidates(ledger,cred.C,w.ell);show=scheme::prove(p,selection.list,selection.index,o,req);});
  w.emit(rep,"OTAC","show",ms,show.payload_bytes().size());
  // Validate the actual wire encoding once per configuration, outside timed crypto operations.
  auto decoded=rep==0?scheme::Show::from_bytes(p,show.bytes()):show;scheme::Ledger consume_ledger=ledger;bool ok=false;
  ms=timed([&]{ok=scheme::verify(p,consume_ledger,req,decoded);});require(ok,"presentation rejected");w.emit(rep,"OTAC","verify",ms,0);
  scheme::TransferResult tr;
  ms=timed([&]{auto selection=scheme::sample_candidates(ledger,cred.C,w.ell);tr=scheme::transfer(p,ledger,selection.list,selection.index,o);});
  w.emit(rep,"OTAC","transfer",ms,tr.proof.payload_bytes().size());
  auto decoded_tr=rep==0?scheme::TransferProof::from_bytes(p,tr.proof.bytes()):tr.proof;scheme::Ledger transfer_ledger=ledger;
  ms=timed([&]{ok=scheme::verify_transfer(p,transfer_ledger,decoded_tr);});require(ok,"transfer rejected");w.emit(rep,"OTAC","verify_transfer",ms,0);
  if(rep==0){
   w.size("OTAC","issuance_request",request.payload_bytes().size(),true,"cryptographic payload excludes auxiliary evidence");
   w.size("OTAC","request_wire",request.bytes().size(),true,"canonical versioned encoding");
   w.size("OTAC","issuance_bilateral",request.payload_bytes().size()+cred.bytes().size(),true,"one request one reply");
   w.size("OTAC","issuance_total",request.payload_bytes().size()+2*cred.bytes().size(),true,"includes one chain registration payload");
   w.size("OTAC","credential",cred.bytes().size(),true,"C and issuer signature");
   w.size("OTAC","show_proof",show.proof_bytes().size(),true,"joint NIZK only");
   w.size("OTAC","presentation",show.payload_bytes().size(),true,"candidate list plus T and integrated proof");
   w.size("OTAC","show_wire",show.bytes().size(),true,"canonical versioned encoding");
   w.size("OTAC","transfer_proof",tr.proof.proof_bytes().size(),true,"includes internal Dtr Utr");
   w.size("OTAC","transfer",tr.proof.payload_bytes().size(),true,"candidate list plus old tag new commitment and proof");
   w.size("OTAC","transfer_wire",tr.proof.bytes().size(),true,"canonical versioned encoding");
  }
  baseline_case(w,rep,common,attrs,req,up,x,he,cy);
  if(rep>=0&&(rep%10==0||rep==reps-1))std::cerr<<w.exp<<" ell="<<w.ell<<" n="<<w.n<<" d="<<w.d<<" rep="<<rep+1<<'/'<<reps<<'\n';
 }
}
int main(int argc,char**argv){try{
 require(argc>=3,"usage: comparison_bench test|bench PARAM [reps=100] [out] [default|all|wide] [ell=64]");
 double init_ms=timed([&]{init(argv[2]);});
 if(std::string(argv[1])=="test"){
  int a=baseline_checks::uprove_checks(),b=baseline_checks::chan_yuen_checks();
  PP p(4);auto o=opening(4);auto req=request(o.a,2);auto ar=acl::register_user(p,o);auto ai=acl::issuer_prepare(p,ar,o.a);auto au=acl::user_prepare(p,ar,ai);
  auto at=acl::user_finish(au,acl::issuer_reply(p,ai,au));require(acl::token_verify(p,at),"ACL completeness");
  auto show=acl::present(p,at,o,au,ai,req);std::set<std::string>spent;require(acl::verify(p,req,show,spent),"ACL present");
  require(!acl::verify(p,req,show,spent),"ACL replay");
  std::cout<<"PASS U-Prove "<<a<<"; Chan-Yuen "<<b<<"; ACL 3 checks\n";return 0;
 }
 require(std::string(argv[1])=="bench","unknown mode");
 int reps=argc>3?std::stoi(argv[3]):100;require(reps>0,"positive repetitions required");
 const std::string grid=argc>5?argv[5]:"default";
 require(grid=="default"||grid=="all"||grid=="wide","unknown measurement grid");
 const bool all=grid=="all";
 const bool wide=grid=="wide";
 const int main_n=wide?wide_attribute_counts.front():default_attribute_count;
 require(argc<=6||std::stoi(argv[6])==default_candidate_count,"the experiment keeps ell fixed");
 const std::string out=argc>4?argv[4]:"results/current";
 require(!std::filesystem::exists(out+"/raw_timings.csv"),"refusing to overwrite measurements; choose a fresh directory");
 std::filesystem::create_directories(out);Writer w(out);
 std::ofstream setup(out+"/setup.csv");setup<<"component,repetition,ms\n";setup<<"pbc_context,0,"<<init_ms<<'\n';
 for(int rep=-3;rep<reps;rep++){double ms=timed([&]{PP p(main_n);scheme::Params rp(p);});if(rep>=0)setup<<"public_parameters_and_key,"<<rep<<','<<ms<<'\n';}
 std::optional<cy22::Paillier> he;
 if(!wide){
  auto start=std::chrono::steady_clock::now();he.emplace(3072);
  double he_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
  setup<<"paillier_3072_keygen,0,"<<he_ms<<'\n';
 }
 setup.close();
 const auto* he_key=he?&*he:nullptr;
 w.ell=default_candidate_count;
 std::ofstream fixtures(out+"/input_attributes.csv");fixtures<<"n,index,encoded_attribute_hex\n";
 w.d=default_match_count;
 auto run_attributes=[&](int n){
  auto attrs=baseline_checks::attributes(n);for(int k=0;k<n;k++){char*hex=mpz_get_str(nullptr,16,attrs[k].v);fixtures<<n<<','<<k<<','<<hex<<'\n';free(hex);}
  w.n=n;w.exp=n==main_n?"algorithms":"attributes";
  run_case(w,reps,he_key);
 };
 if(wide){
  for(int n:wide_attribute_counts)run_attributes(n);
 }else{
  const int largest_n=all?max_benchmark_attribute_count:default_attribute_count;
  for(int n=default_attribute_count;n<=largest_n;++n)run_attributes(n);
 }
 if(all||wide){
  w.n=wide?wide_match_attribute_count:max_benchmark_attribute_count;
  w.exp="match_counts";
  auto run_matches=[&](int d){
   if(d==default_match_count)return;
   w.d=d;run_case(w,reps,he_key);
  };
  if(wide){
   for(int d:wide_match_counts)run_matches(d);
  }else{
   for(int d=1;d<=w.n;++d)run_matches(d);
  }
 }
 std::cout<<"Completed measurements: "<<out<<'\n';return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}



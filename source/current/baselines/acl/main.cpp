#include "acl.hpp"
using namespace otac;
int main(int argc,char**argv){
 try{
  require(argc==2,"usage: acl_reproduction PARAMETER_FILE");init(argv[1]);PP p(16);
  for(int rep=0;rep<10;rep++){
   auto o=opening(16);auto r=request(o.a,4);
   auto registration=acl::register_user(p,o);
   auto issuer=acl::issuer_prepare(p,registration,o.a);
   auto holder=acl::user_prepare(p,registration,issuer);
   auto token=acl::user_finish(holder,acl::issuer_reply(p,issuer,holder));
   require(acl::token_verify(p,token),"ACL token rejected");
   auto show=acl::present(p,token,o,holder,issuer,r);std::set<std::string>spent;
   require(acl::verify(p,r,show,spent),"ACL presentation rejected");
   require(!acl::verify(p,r,show,spent),"ACL replay accepted");
  }
  std::cout<<"PASS independent ACL reproduction: 10 complete lifecycles\n";return 0;
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}
}

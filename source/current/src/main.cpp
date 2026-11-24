#include "../tests/protocol_checks.hpp"
using namespace otac;
#ifndef OTAC_USE_P256
static void generate_params(const std::string& path,int bits){
 pbc_random_set_function(secure_pbc_random,nullptr);pbc_param_t par;
 pbc_param_init_f_gen(par,bits);FILE* f=fopen(path.c_str(),"wb");require(f,"cannot write parameters");
 pbc_param_out_str(f,par);fclose(f);pbc_param_clear(par);
}
#endif
int main(int argc,char**argv){try{
 require(argc>=3,"usage: credential_bench test|info|param PARAM [bits]; experiments use comparison_bench bench PARAM");
 const std::string mode=argv[1];
#ifndef OTAC_USE_P256
 if(mode=="param"){generate_params(argv[2],argc>3?std::stoi(argv[3]):512);return 0;}
#endif
 double init_ms=timed([&]{init(argv[2]);});
 if(mode=="test"){scheme::run_tests();return 0;}
 if(mode=="info"){
  G g=G::hash("metadata");
  std::cout<<"{\"revision\":\"anonymous-attribute-credentials\",\"challenge_bits\":128,"
#ifdef OTAC_USE_P256
   <<"\"curve\":\"prime256v1\",\"field_bits\":256,\"group_backend\":\"OpenSSL EC\","
   <<"\"openssl\":\""<<OpenSSL_version(OPENSSL_VERSION)<<"\","
   <<"\"hash_to_curve\":\"P256_XMD:SHA-256_SSWU_RO_\","
#else
   <<"\"pbc\":\"1.0.0\","
#endif
   <<"\"order_bits\":"<<order_bits
   <<",\"scalar_bytes\":"<<scalar_bytes<<",\"group_bytes\":"<<g.bytes().size()
   <<",\"show_wire_version\":\""<<scheme::Show::wire_version<<"\",\"gmp_runtime\":\""<<gmp_version
   <<"\",\"context_init_ms\":"<<init_ms<<"}\n";return 0;
 }
 throw std::runtime_error("unknown mode; experiments run through comparison_bench");
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

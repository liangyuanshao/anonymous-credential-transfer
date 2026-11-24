#include "../protocol_checks.hpp"
int main(int argc,char**argv){try{otac::require(argc==2,"usage: chan_yuen_reproduction PARAM");otac::init(argv[1]);std::cout<<"PASS Chan-Yuen core / AND: "<<baseline_checks::chan_yuen_checks()<<" checks (NOT complete malicious-secure issuance)\n";return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

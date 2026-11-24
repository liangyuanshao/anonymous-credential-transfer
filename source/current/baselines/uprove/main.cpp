#include "../protocol_checks.hpp"
int main(int argc,char**argv){try{otac::require(argc==2,"usage: uprove_reproduction PARAM");otac::init(argv[1]);std::cout<<"PASS U-Prove: "<<baseline_checks::uprove_checks()<<" checks\n";return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}

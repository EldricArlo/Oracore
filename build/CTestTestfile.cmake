# CMake generated Testfile for 
# Source directory: D:/C/Oracipher-core
# Build directory: D:/C/Oracipher-core/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_api_integration "D:/C/Oracipher-core/build/test_api_integration.exe")
set_tests_properties(test_api_integration PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")
add_test(test_asymmetric_crypto "D:/C/Oracipher-core/build/test_asymmetric_crypto.exe")
set_tests_properties(test_asymmetric_crypto PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")
add_test(test_core_crypto "D:/C/Oracipher-core/build/test_core_crypto.exe")
set_tests_properties(test_core_crypto PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")
add_test(test_expert_api "D:/C/Oracipher-core/build/test_expert_api.exe")
set_tests_properties(test_expert_api PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")
add_test(test_kdf "D:/C/Oracipher-core/build/test_kdf.exe")
set_tests_properties(test_kdf PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")
add_test(test_pki_verification "D:/C/Oracipher-core/build/test_pki_verification.exe")
set_tests_properties(test_pki_verification PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")
add_test(test_symmetric_crypto "D:/C/Oracipher-core/build/test_symmetric_crypto.exe")
set_tests_properties(test_symmetric_crypto PROPERTIES  ENVIRONMENT "HSC_PEPPER_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" _BACKTRACE_TRIPLES "D:/C/Oracipher-core/CMakeLists.txt;125;add_test;D:/C/Oracipher-core/CMakeLists.txt;0;")

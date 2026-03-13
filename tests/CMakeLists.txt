add_executable(shatters-tests
    smoke_test.cpp
    crypto/test_secure_memory.cpp
    crypto/test_keys.cpp
    crypto/test_kdf.cpp
    crypto/test_hash.cpp
    crypto/test_aead.cpp
)

target_link_libraries(shatters-tests
    PRIVATE
        shatters-sdk
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(shatters-tests)

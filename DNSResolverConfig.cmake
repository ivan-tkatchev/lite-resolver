add_library(dns_resolver STATIC IMPORTED)
find_library(DNSResolver_LIBRARY_PATH dns_resolver HINTS "${CMAKE_CURRENT_LIST_DIR}/../../")
set_target_properties(dns_resolver PROPERTIES IMPORTED_LOCATION "${DNSResolver_LIBRARY_PATH}")

// C ABI over Ada (ada-url/ada, single-file amalgamation): the WHATWG host parser's domain-to-ASCII as Node's url.domainToASCII does it
// (set the hostname of "ws://x" and read it back: UTS 46 non-transitional, CheckBidi, forbidden host code points, IPv4 numbers).
#include "ada.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#if defined(_WIN32)
#define ATLAS_EXPORT extern "C" __declspec(dllexport)
#else
#define ATLAS_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// 1 and the A-label host in out / out_len on success; 0 when the host is refused, empty, or does not fit in cap.
ATLAS_EXPORT int atlas_ada_domain_to_ascii(const uint8_t *input, size_t input_len, uint8_t *out, size_t cap, size_t *out_len) {
  if (input == nullptr || out == nullptr || out_len == nullptr || input_len == 0) return 0;
  auto url = ada::parse<ada::url>("ws://x");
  if (!url) return 0;
  if (!url->set_hostname(std::string_view(reinterpret_cast<const char *>(input), input_len))) return 0;
  std::string host(url->get_hostname());
  if (host.empty() || host.size() > cap) return 0;
  std::memcpy(out, host.data(), host.size());
  *out_len = host.size();
  return 1;
}

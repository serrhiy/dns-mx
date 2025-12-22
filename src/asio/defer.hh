#pragma once

#include <tuple>
#include <type_traits>
#include <utility>

namespace utils {
template <typename T, typename... Args>
class defer final {
  T callback;
  std::tuple<Args...> args;

 public:
  template <typename F, typename... A>
  defer(F&& collable, A&&... args)
      : callback{std::forward<F>(collable)}, args{std::forward<A>(args)...} {}

  defer(const defer&) = delete;
  defer& operator=(const defer&) = delete;

  defer(const defer&&) = delete;
  defer& operator=(defer&&) = delete;

  ~defer() { std::apply(callback, args); }
};

template <typename F, typename... A>
defer(F&&, A&&...) -> defer<std::decay_t<F>, std::decay_t<A>...>;
}

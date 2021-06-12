#include<iostream>
#include<vector>
#include<string>
#include <array>
#include <cstdint>
#include <iostream>
#include <iomanip>


using namespace std;



vector<int> X;//8*64=512, each subscript stores 8 bits

int W[80];//32 bits as a group

int A, B, C, D, E;

int A1, B1, C1, D1, E1; // buffer register, produce the final result

int Turn; // number of encrypted packets


int S(unsigned int x, int n) {//cycle left shift

    return x >> (32 - n) | (x << n);

}

void append(string m) {//text fill processing

    Turn = (m.size() + 8) / 64 + 1;

    X.resize(Turn * 64);

    int i = 0;

    for (; i < m.size(); i++) {

        X[i] = m[i];

    }

    X[i++] = 0x80;

    while (i < X.size() - 8) {

        X[i] = 0;

        i++;

    }

    long long int a = m.size() * 8;

    for (i = X.size() - 1; i >= X.size() - 8; i--) {

        X[i] = a % 256;

        a /= 256;

    }

}

void setW(vector<int> m, int n) {//W array generation

    n *= 64;

    for (int i = 0; i < 16; i++) {

        W[i] = (m[n + 4 * i] << 24) + (m[n + 4 * i + 1] << 16)

            + (m[n + 4 * i + 2] << 8) + m[n + 4 * i + 3];

    }

    for (int i = 16; i < 80; i++) {

        W[i] = S(W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3], 1);

    }

}

int ft(int t) {//ft(B,C,D) function

    if (t < 20)

        return (B & C) | ((~B) & D);

    else if (t < 40)

        return B ^ C ^ D;

    else if (t < 60)

        return (B & C) | (B & D) | (C & D);

    else

        return B ^ C ^ D;

}

 int Kt(int t) {//constant K

    if (t < 20)

        return 0x5a827999;

    else if (t < 40)

        return 0x6ed9eba1;

    else if (t < 60)

        return 0x8f1bbcdc;

    else

        return 0xca62c1d6;

}

void sha1(string text) {

    A1 = A = 0x67452301;

    B1 = B = 0xefcdab89;

    C1 = C = 0x98badcfe;

    D1 = D = 0x10325476;

    E1 = E = 0xc3d2e1f0;

    append(text);

    for (int i = 0; i < Turn; i++) {

        setW(X, i);

        for (int t = 0; t < 80; t++) {

            int temp = E + ft(t) + S(A, 5) + W[t] + Kt(t);

            E = D;

            D = C;

            C = S(B, 30);

            B = A;

            A = temp;

        }

        A1 = A = A + A1;

        B1 = B = B + B1;

        C1 = C = C + C1;

        D1 = D = D + D1;

        E1 = E = E + E1;

    }

    printf("%08x%08x%08x%08x%08x\n\n", A1, B1, C1, D1, E1);

}

// HASH MD5

namespace ConstexprHashes {

// operaciones MD5
constexpr uint32_t f(uint32_t x, uint32_t y, uint32_t z) {
    return z ^ (x & (y ^ z));
}

constexpr uint32_t g(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (z & (x ^ y));
}

constexpr uint32_t h(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

constexpr uint32_t i(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (x | ~z);
}

constexpr uint32_t step_helper(uint32_t fun_val, uint32_t s, uint32_t b) {
    return ((fun_val << s) | ((fun_val & 0xffffffff) >> (32 - s))) + b;
}

template<typename Functor>
constexpr uint32_t step(Functor fun, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t t, uint32_t s) {
    return step_helper(a + fun(b, c, d) + x + t, s, b);
}

constexpr uint32_t data32(const char* data, size_t n) {
    return (static_cast<uint32_t>(data[n * 4]) & 0xff) |
            ((static_cast<uint32_t>(data[n * 4 + 1]) << 8) & 0xff00) |
            ((static_cast<uint32_t>(data[n * 4 + 2]) << 16) & 0xff0000) |
            ((static_cast<uint32_t>(data[n * 4 + 3]) << 24) & 0xff000000);
}

// Constantes

constexpr std::array<uint32_t, 64> md5_constants = {{
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,
    0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,
    0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,
    0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,
    0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
    0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
}};

constexpr std::array<size_t, 64> md5_shift = {{
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,
    5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
}};

constexpr std::array<size_t, 64> md5_indexes = {{
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1,6,11,0,5,10,15,4,
    9,14,3,8,13,2,7,12,5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
    0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
}};

constexpr std::array<decltype(f)*, 4> md5_functions = {{
    f, g, h, i
}};

template<size_t... indexes>
struct index_tuple {};

template<size_t head, size_t... indexes>
struct index_tuple<head, indexes...> {
    typedef typename index_tuple<head-1, head-1, indexes...>::type type;
};

template<size_t... indexes>
struct index_tuple<0, indexes...> {
    typedef index_tuple<indexes...> type;
};

template<typename... Args>
struct index_tuple_maker {
    typedef typename index_tuple<sizeof...(Args)>::type type;
};

template<size_t n, size_t i>
struct buffer_builder {
    static constexpr char make_value(const char *data) {
        return (i <= n) ? data[i] : 0;
    }
};

template<size_t n>
struct buffer_builder<n, n> {
    static constexpr char make_value(const char *) {
        return 0x80;
    }
};

template<size_t n>
struct buffer_builder<n, 56> {
    static constexpr char make_value(const char *) {
        return n << 3;
    }
};

template<typename T, size_t n>
struct constexpr_array {
    const T array[n];

    constexpr const T *data() const {
        return array;
    }
};

typedef constexpr_array<char, 64> buffer_type;

template<size_t n, size_t... indexes>
constexpr buffer_type make_buffer_helper(const char (&data)[n], index_tuple<indexes...>) {
    return buffer_type{{ buffer_builder<n - 1, indexes>::make_value(data)... }};
}

template<size_t n>
constexpr buffer_type make_buffer(const char (&data)[n]) {
    return make_buffer_helper(data, index_tuple<64>::type());
}

typedef std::array<char, 16> md5_type;

template<size_t n, size_t rot>
struct md5_step;

constexpr md5_type make_md5_result(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    typedef md5_type::value_type value_type;
    return md5_type{{
        static_cast<value_type>(a & 0xff), static_cast<value_type>((a & 0xff00) >> 8),
        static_cast<value_type>((a & 0xff0000) >> 16), static_cast<value_type>((a & 0xff000000) >> 24),

        static_cast<value_type>(b & 0xff), static_cast<value_type>((b & 0xff00) >> 8),
        static_cast<value_type>((b & 0xff0000) >> 16), static_cast<value_type>((b & 0xff000000) >> 24),

        static_cast<value_type>(c & 0xff), static_cast<value_type>((c & 0xff00) >> 8),
        static_cast<value_type>((c & 0xff0000) >> 16), static_cast<value_type>((c & 0xff000000) >> 24),

        static_cast<value_type>(d & 0xff), static_cast<value_type>((d & 0xff00) >> 8),
        static_cast<value_type>((d & 0xff0000) >> 16), static_cast<value_type>((d & 0xff000000) >> 24),
    }};
}

template<>
struct md5_step<64, 0> {
    static constexpr md5_type do_step(const char *, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        return make_md5_result(a + 0x67452301, b + 0xefcdab89, c + 0x98badcfe, d + 0x10325476);
    }
};

template<size_t n>
struct md5_step<n, 3> {
    static constexpr md5_type do_step(const char *data, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        return md5_step<n + 1, (n + 1) % 4>::do_step(data, a, step(md5_functions[n / 16], b, c, d, a, data32(data, md5_indexes[n]), md5_constants[n], md5_shift[n]), c, d);
    }
};

template<size_t n>
struct md5_step<n, 2> {
    static constexpr md5_type do_step(const char *data, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        return md5_step<n + 1, (n + 1) % 4>::do_step(data, a, b, step(md5_functions[n / 16], c, d, a, b, data32(data, md5_indexes[n]), md5_constants[n], md5_shift[n]), d);
    }
};

template<size_t n>
struct md5_step<n, 1> {
    static constexpr md5_type do_step(const char *data, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        return md5_step<n + 1, (n + 1) % 4>::do_step(data, a, b, c, step(md5_functions[n / 16], d, a, b, c, data32(data, md5_indexes[n]), md5_constants[n], md5_shift[n]));
    }
};

template<size_t n>
struct md5_step<n, 0> {
    static constexpr md5_type do_step(const char *data, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
        return md5_step<n + 1, (n + 1) % 4>::do_step(data, step(md5_functions[n / 16], a, b, c, d, data32(data, md5_indexes[n]), md5_constants[n], md5_shift[n]), b, c, d);
    }
};

template<size_t n>
constexpr md5_type md5(const char (&data)[n]) {
    return md5_step<0, 0>::do_step(make_buffer(data).data(), 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
}

} // namespace ConstexprHashes

using namespace std;

int main() {

    cout << "\"perro\" en sha-1: " << endl;
    sha1("perro");
    
    cout << "\"perro\" en MD5: " << endl;
    
    auto hash = ConstexprHashes::md5("perro");
    cout << hex;
    for (auto i : hash) {
        cout << (static_cast<int>(i) & 0xff);
    }
    cout << endl;
    
}

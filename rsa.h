#ifndef RSA_H
#define RSA_H

#include <iostream> //cout、endl、string
#include <vector>   // vector
#include <string>
#include <QRandomGenerator>

using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::vector;

class RSA
{
public:
    RSA();                                                                            // khởi tạo
    static vector<unsigned int> Encrypt(const string &plaintext_str, unsigned int e, unsigned int n);  // mã hóa
    static QString Decrypt(const vector<unsigned int> &ciphertext_int, unsigned int d, unsigned int n); // Giải mã

private:
    void KeyGen(); // Tạo khóa

    unsigned int GetPrimeNum();                                                                    // Nhận số nguyên tố
    bool PrimalityTest(const unsigned int &n, const unsigned int &a);                              // Miller-Rabin (kiểm tra tính nguyên tố)
    static unsigned int QuickPowMod(const unsigned int &a, const unsigned int &q, const unsigned int &n); // lũy thừa mô đun nhanh Montgomery
    static unsigned int QuickMulMod(const unsigned int &a, const unsigned int &b, const unsigned int &c); // Lấy mẫu nhanh

    unsigned int ExGcd(const unsigned int &a, const unsigned int &b, unsigned int &x, unsigned int &y); // Thuật toán Euclide mở rộng
    unsigned int GetMulInverse(const unsigned int &a, const unsigned int &b);                           // Tìm nghịch đảo của phép nhân

public:
    unsigned int p_arg_; // tham số p
    // Mẹo: Tham số >=0, sử dụng unsigned int sẽ có ngữ nghĩa hơn
    unsigned int q_arg_;            // tham số q
    unsigned int n_arg_;            // tham số n
    unsigned int n_Euler_func_arg_; // Tham số hàm Euler của n
    unsigned int e_arg_;            // tham số e
    unsigned int d_arg_;            // tham số d
};

#endif // RSA_H

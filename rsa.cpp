#include "rsa.h"
#include <QString>
#include <ctime>   //time()
#include <cstdlib> //srand()、rand()
const unsigned int MIN_PRIME_NUM = 10;
const unsigned int MAX_PRIME_NUM = 1000;

// Khởi tạo
RSA::RSA()
{
    this->KeyGen(); // Tạo khóa

    cout << "Tao khoa: \t" << endl;
    cout << "Tham so p: \t" << this->p_arg_ << endl;
    cout << "Tham so q: \t" << this->q_arg_ << endl;
    cout << "Tham so n: \t" << this->n_arg_ << endl;
    cout << "Ham Euler cua tham so n: \t" << this->n_Euler_func_arg_ << endl;
    cout << "Tham so e: \t" << this->e_arg_ << endl;
    cout << "Tham so d: \t" << this->d_arg_ << endl;
    cout << endl;
}

// Mã hóa
// (Tham số: văn bản thuần túy của loại chuỗi)
// (Trả về: bản mã của số nguyên không dấu)
vector<unsigned int> RSA::Encrypt(const string &plaintext_str, unsigned int e, unsigned int n)
{
    cout << "Ma hoa:\t" << endl;
    cout << "Van ban don gian cua loai chuoi:\t" << plaintext_str << endl;

    // 1.Chuyển đổi kiểu dữ liệu chuỗi văn bản thuần túy thành kiểu số nguyên không dấu theo mã ASCII
    unsigned int p = 0; // nhóm văn bản thuần túy   (1 ký tự và 1 số là 1 nhóm văn bản thuần túy)
    // Mẹo: Yêu cầu nhóm văn bản thuần túy P < tham số n, theo phạm vi ASCII 0 ~ 255 phải < n, không còn được xử lý
    vector<unsigned int> plaintext_int(plaintext_str.size(), 0); // văn bản thuần túy của kiểu số nguyên không dấu (1 ký tự là 1 số)

    for (unsigned int i = 0; i < plaintext_str.size(); ++i)
    {
        p = plaintext_str[i]; // Lưu ý: Tận dụng tính năng chuyển đổi kiểu tự động
        plaintext_int[i] = (p);
    }

    cout << "Van ban thuan tuy cua kieu so nguyen khong dau:\t";
    for (int num : plaintext_int)
    {
        cout << num << " ";
    }
    cout << endl;

    // 2.mã hóa
    unsigned int c = 0; // Nhóm văn bản mật mã (Một bản rõ kỹ thuật số được mã hóa để thu được một bản mã kỹ thuật số và một số là nhóm bản mã.)
    vector<unsigned int> ciphertext_int(plaintext_str.size(), 0); // Bản mã kiểu số nguyên không dấu
    for (unsigned int i = 0; i < plaintext_int.size(); ++i) // Đối với mỗi nhóm bản rõ, mã hóa lũy thừa mô-đun nhanh Montgomery
    {
        c = QuickPowMod(plaintext_int[i], e, n);
        ciphertext_int[i] = c;
    }

    cout << "Ban ma kieu so nguyen khong dau:\t";           //Bản mã kiểu số nguyên không dấu
    for (int num : ciphertext_int)
    {
        cout << num << " ";
    }
    cout << endl;
    cout << endl;

    return ciphertext_int;
}

// Giải mã
QString RSA::Decrypt(const vector<unsigned int> &ciphertext_int, unsigned int d, unsigned int n)
{
    cout << "Giai ma:\t" << endl;           // Giải mã
    cout << "Ban ma kieu so nguyen khong dau:\t";           // Bản mã kiểu số nguyên không dấu
    for (int num : ciphertext_int)
    {
        cout << num << " ";
    }
    cout << endl;

    // 1.Giải mã
    long long p = 0;                                           // Nhóm bản rõ: 1 bản mã số được giải mã để thu được 1 bản rõ số và 1 số là nhóm bản rõ.
    vector<unsigned int> plaintext_int(ciphertext_int.size(), 0); // Văn bản thuần túy kiểu số nguyên không dấu: 1 ký tự bằng 1 số

    for (unsigned int i = 0; i < ciphertext_int.size(); ++i) // Đối với mỗi nhóm bản mã, giải mã lũy thừa mô đun nhanh Montgomery
    {
        p = QuickPowMod(ciphertext_int[i], d, n);
        plaintext_int[i] = p;
    }

    cout << "Van ban thuan tuy cua kieu so nguyen khong dau:\t";        // văn bản thuần túy của kiểu số nguyên không dấu
    for (int num : plaintext_int)
    {
        cout << num << " ";
    }
    cout << endl;

    // 2.Chuyển đổi loại số nguyên không dấu văn bản thuần túy thành loại dữ liệu chuỗi theo mã ASCII
    QString res_str;
    for (unsigned int i = 0; i < plaintext_int.size(); ++i)
    {
        res_str.append(QChar::fromLatin1(static_cast<char>(plaintext_int[i]))); // 注意：利用强制类型转换 (Lưu ý: Sử dụng diễn viên)
    }

    cout << "Van ban don gian cua loai chuoi:\t" << res_str.toStdString() << endl;  // văn bản đơn giản của loại chuỗi

    return res_str;
}

// Tạo khóa
void RSA::KeyGen()
{
    // 1. Chọn p, q. p và q là số nguyên tố, p không bằng q
    // Lưu ý: Đặt phần tách hạt ngẫu nhiên bên ngoài vòng lặp và
    //    bên ngoài cùng một hàm để tránh lấy cùng số ngẫu nhiên ở những thời điểm giống nhau.
    unsigned int seed = time(nullptr); // hạt giống ngẫu nhiên
    srand(seed);                       // Đặt hạt giống ngẫu nhiên

    this->p_arg_ = this->GetPrimeNum(); // Nhận tham số p
    this->q_arg_ = this->GetPrimeNum(); // Nhận tham số q

    // 2. Tính n = p × q
    this->n_arg_ = this->p_arg_ * this->q_arg_;
    // Mẹo: Khi viết tiếng Trung lần đầu tiên mình dùng dấu × thay vì *...

    // 3. Tính hàm Euler của n = (p - 1) × (q - 1)
    this->n_Euler_func_arg_ = (this->p_arg_ - 1) * (this->q_arg_ - 1);

    // 4. Chọn e. e là một số nguyên, hàm Euler của e và n là nguyên tố cùng nhau và hàm Euler của 1 < e < n
    // Chọn 3 hoặc 17 hoặc 65537. e càng lớn thì d tương đối càng nhỏ.Hai giá trị tương đối cân bằng.
    // Lưu ý: Các hàm Euler của e và n là nguyên tố cùng nhau và không thể coi là hiển nhiên.
    if (this->n_Euler_func_arg_ % 65537 != 0)
    {
        this->e_arg_ = 65537;
    }
    else if (this->n_Euler_func_arg_ % 17 != 0)
    {
        this->e_arg_ = 17;
    }
    else if (this->n_Euler_func_arg_ % 3 != 0)
    {
        this->e_arg_ = 3;
    }
    else // Tình huống cực kỳ gần như không thể
    {
        cerr << "Khong the chon tham so e" << endl;
        exit(EXIT_FAILURE); // Chương trình thoát trực tiếp
    }

    // 5. Tính toán d. Hàm Euler của d × e % n = 1, Hàm Euler của d < n
    this->d_arg_ = GetMulInverse(this->e_arg_, this->n_Euler_func_arg_);
    // Lưu ý: hàm Euler cho n chứ không phải cho tham số n

    return;
}

// Nhận số nguyên tố
unsigned int RSA::GetPrimeNum()
{
    unsigned int random = 0;     // số ngẫu nhiên
    unsigned int random_odd = 0; // số lẻ ngẫu nhiên

    unsigned int n = 0;              // Tham số n của kiểm tra tính nguyên tố cần được khởi tạo lại trong vòng lặp.
    unsigned int a = 0;              //Thông số a của kiểm tra tính nguyên tố
    bool primality_test_res = false; // Kết quả kiểm tra tính nguyên tố: false không phải là số nguyên tố, true có thể là số nguyên tố
    bool prime_flag = false;         // Cờ số nguyên tố, kết quả kiểm tra tính nguyên tố cuối cùng. false0 không phải là số nguyên tố, true1 có thể là số nguyên tố
    // Mẹo: Khi khởi tạo các biến bên ngoài vòng lặp, hãy chú ý xem chúng cần được cập nhật hay khởi tạo lại trong vòng lặp.

    while (true) // vòng lặp
    {
        // 1.1Chọn ngẫu nhiên một số lẻ có kích thước mong muốn
        // 1.1.1Nhận số ngẫu nhiên
        // Các số ngẫu nhiên thường có từ 4 đến 5 chữ số và không vượt quá phạm vi biểu diễn của unsigned int.
        random = QRandomGenerator::global()->bounded(MIN_PRIME_NUM, MAX_PRIME_NUM);

        // 1.1.2 Lấy một số lẻ
        if (random % 2 == 0) // Nếu là số chẵn thì +1 trở thành số lẻ
        {
            random_odd = random + 1;
        }
        else // Không có thao tác bổ sung cho số lẻ
        {
            random_odd = random;
        }

        // 1.2 Sử dụng thử nghiệm nguyên tố để xác định
        n = random_odd;

        for (int i = 0; i < 128; ++i) // Chọn 128 thông số a và kiểm tra 128 lần
        {
            //  1.2.1 Chọn ngẫu nhiên các thông số liên quan a. Thỏa mãn a là số nguyên, 1 < a < n - 1
            a = rand() % (n - 1); // 0 ~ n - 2
            // Để ý:
            // Vì khoảng thời gian chạy tương tự nhau nên số ngẫu nhiên được lấy lần đầu a có thể bằng n.
            // Khi đó kết quả tính toán phải là 1, rồi 1 + 1 = 2
            // Sau khi giải nén hàm bằng cách đặt mã hạt ngẫu nhiên thì loại bỏ lỗi này
            if (a == 0) // Nếu bằng 0 thì a = 2 > 1
            {
                a += 2;
            }
            if (a == 1) // Nếu là 1 thì a = 2 > 1
            {
                ++a;
            }

            primality_test_res = PrimalityTest(random_odd, a); // bài kiểm tra năng lực

            if (primality_test_res == true) // Kết quả của phép thử có thể là số nguyên tố
            {
                prime_flag = true; // Điểm đánh dấu có thể là số nguyên tố
            }
            else if (primality_test_res == false) // Miễn là có một phép kiểm tra tính nguyên tố không phải là số nguyên tố thì nó không được là số nguyên tố.
            {
                prime_flag = false;

                break; // Không còn dùng bài kiểm tra, cần chọn lại số lẻ ngẫu nhiên
            }
        }

        if (prime_flag == true) // Số lẻ ngẫu nhiên có thể là số nguyên tố
        {
            break; // thoát khỏi vòng lặp
        }
        // Nếu không, số lẻ ngẫu nhiên không phải là số nguyên tố, hãy nhập vòng lặp,
        //  sau đó lặp lại các bước 1.1 để lấy số lẻ ngẫu nhiên và 1.2 để kiểm tra tính nguyên tố.
    }

    return random_odd; // Nhận số nguyên tố
}

// Thử nghiệm nguyên thủy Miller-Rabin
bool RSA::PrimalityTest(const unsigned int &n, const unsigned int &a) // 参数：随机奇数，参数a
{
    // 1.2.2 Tìm các tham số liên quan k, q. Thỏa mãn n - 1 = 2^k × q. k và q là số nguyên, k > 0, q là số lẻ
    unsigned int k = 0;
    unsigned int q = n - 1;

    // gợi ý:
    // Nhiều thuật toán chỉ giải thích cách tìm k và q mà không nói cách tìm chúng.
    // Mã để tìm k và q cũng mơ hồ.
    while ((q & 1) == 0)
    {
        ++k;
        q >>= 1;
    }
    // hiểu:
    // q & 1: Nghĩa là, biểu diễn nhị phân của q được AND với bit nhị phân 1 và bit thấp nhất của biểu diễn nhị phân của q là 0 hoặc 1.
    // Chẳng hạn như 101 & 1 = 101 & 001 = 001 = 1
    // Chẳng hạn như 0010 & 1 = 0010 & 0001 = 0

    // Ở bit thấp nhất, cơ số 2^0 = 1, vì vậy nếu giá trị là 0 thì 1 × 0 = 0 là số chẵn; nếu giá trị là 1 thì 1 × 1 = 1 là số lẻ
    // Do đó, nếu kết quả của phép tính là 0 thì đó là số chẵn và có thể rút ra hệ số 2
    // while: Trích xuất liên tục hệ số 2
    // Mỗi lần rút ra thừa số 2 thì ++k, k là số đếm của thừa số 2
    // q >>= 1: Chuyển biểu diễn nhị phân của q sang phải và giảm bớt, đồng thời xét bit thấp nhất để trích ra hệ số 2
    // Cho đến khi không thể trích xuất được yếu tố 2 liên tục thì q là giá trị mong muốn

    // Ví dụ: số thập phân 13 - 1 = 12 = nhị phân 1100, hệ số 2 được trích từ bit thứ 1 và thứ 2 là 2^2 = 4
    // Vậy 12 = 2^2 × 3. k = 2, q = 3
    // Ví dụ thập phân 7 - 1 = 6 = nhị phân 110, trích 1 thừa số 2 ở vị trí thứ 1 là 2^1 = 2
    // Vậy 6 = 2^1 × 3. k = 1, q = 3

    // Mẹo: Hãy chú ý đến các điều kiện giá trị của k và q
    // Đối với các số nguyên tố nguyên dương, ngoại trừ số 2 là số chẵn thì các số còn lại phải là số lẻ.
    // Số lẻ -1 phải là số chẵn và phải trích ít nhất một thừa số chung 2 thì k ít nhất 1 > 0, thỏa mãn
    // Theo tính chất của thuật toán, nếu trích được tất cả các thừa số chung 2 thì kết quả q phải là số lẻ và thỏa mãn
    // Nói chung, số q rất lớn nên thuật toán lũy thừa mô đun nhanh Montgomery cần được sử dụng trong bước tiếp theo.

    // 1.2.3 Tính a^q %n
    unsigned int aq_mod_n = this->QuickPowMod(a, q, n);

    // cout << n << endl;
    // cout << k << endl;
    // cout << q << endl;
    // cout << a << endl;
    // cout << aq_mod_n << endl;

    // 1.2.4 Phán đoán mệnh đề nghịch đảo bằng định lý phát hiện bậc hai
    // Mệnh đề chính là: phát hiện. Nếu tất cả các nghiệm chỉ là 1 hoặc n-1 thì đó có thể là số nguyên tố.
    // Mệnh đề nghịch đảo có lẽ là: phát hiện, nếu có một nghiệm không phải là 1 và không phải n-1 thì nó không phải là số nguyên tố.
    // Bạn có thể sử dụng những mệnh đề tích cực hoặc những mệnh đề tiêu cực để phán xét.
    //    Sử dụng các mệnh đề tích cực và mệnh đề ngược để đánh giá các mệnh đề sau
    // Điều kiện phán đoán thứ nhất: khi không phát hiện được a ^ q % n == 1 thì có thể là số nguyên tố
    if (aq_mod_n == 1)
    {
        return true;
    }

    // Điều kiện phán đoán thứ hai: Trong lần phát hiện thứ hai,
    //    miễn là nó không phải là 1 và không phải n-1 thì nó không được là số nguyên tố.
    for (unsigned int j = 0; j < k; ++j) // 0 ~ k-1
    {
        aq_mod_n = this->QuickPowMod(aq_mod_n, 2, n);
        // Việc thăm dò thứ cấp của chuỗi tính toán a ^ (q × 2 ^ j) % n = aq_mod_n ^ (2 ^ j) % n.
        //    Mỗi vòng lặp được nâng lên lũy thừa 2 tương đương với (2^j)
        if (aq_mod_n != 1 && aq_mod_n != n - 1)
        {
            return false;
        }
    }
    return true;
    // Điều kiện phán đoán thứ hai: Trong lần phát hiện thứ hai,
    //     nếu nó không được trả về vì được đánh giá là số tổng hợp thì có thể là số nguyên tố.
}

// lũy thừa mô đun nhanh Montgomery
// Thông số: a^q %n
// Giá trị trả về: a^q %n
unsigned int RSA::QuickPowMod(const unsigned int &a, const unsigned int &q, const unsigned int &n)
{
    // nguyên tắc:
    //  Thuộc tính hoạt động công suất: a ^ q = a ^ q1 × a ^ q2. q = q1 + q2
    //  Thuộc tính hoạt động mô-đun: (a × b) % n = [(a % n) × (b % n)] % n
    // Bởi vì: a ^ q % n = (a ^ q1 × a ^ q2) % n = [(a ^ q1 % n) × (a ^ q2 % n)] % n
    unsigned int res = 1;
    unsigned int a_temp = a; // Giá trị của a sẽ được thay đổi trong quá trình hoạt động và được lưu trữ tạm thời.
    unsigned int q_temp = q; // Giá trị của q sẽ được thay đổi trong quá trình hoạt động và được lưu trữ tạm thời.

    // Mẹo: Nhiều mã thuật toán không rõ ràng
    while (q_temp > 0)
    {
        if ((q_temp & 1) == 1)
        {
            res = QuickMulMod(res, a_temp, n);
        }

        a_temp = QuickMulMod(a_temp, a_temp, n);

        q_temp >>= 1;
    }
    // hiểu:
    // Các thuật toán hoạt động trên biểu diễn nhị phân của số thập phân

    // while (q_temp > 0)：So sánh nội dung kiểm tra tính nguyên thủy: while ((q & 1) == 0)
    // Đây là giá trị phán đoán, cần phán đoán tất cả các bit nhị phân,
    //     miễn là giá trị của q không bằng 0 trong lần dịch chuyển phải tiếp theo, nó sẽ lặp.
    //     Trong bài kiểm tra tính nguyên thủy, đó là vị trí phán đoán.

    // if ((q_temp & 1) == 1)：Khi bit thấp nhất là 1, bit đó hợp lệ và kết quả cần được tính toán và cập nhật.
    // Thuật toán nhân nhanh: res = (res × a_temp) % n
    // Bước này tương đương với việc tính một (a^q2 % n) mỗi lần, sau đó nhân nó với kết quả mới (a^q1 % n) trước đó
    // res đầu tiên là kết quả cập nhật, res thứ hai là kết quả trước đó, và a_temp là cơ sở hiện tại.
    // Cơ sở: Cơ sở được cập nhật cho từng bit trong vòng lặp (xem các bước sau). Khi biểu diễn nhị phân là 1, cơ sở là hợp lệ.

    // a_temp = QuickMulMod(a_temp, a_temp, n); tương đương với a_temp = a_temp × a_temp % n
    // Ví dụ: a_temp = 2 ban đầu sẽ được cập nhật liên tục thành 2^0 = 1, 2^1 = 2
    // Sau đó thực hiện % để đảm bảo cơ số không vượt quá phạm vi

    return res;
}

// 快速乘
// Các tham số: a * b % c
// Giá trị trả về: a * b % c
unsigned int RSA::QuickMulMod(const unsigned int &a, const unsigned int &b, const unsigned int &c)
{
    // nguyên tắc:
    // Tương tự như hoạt động mô-đun năng lượng nhanh, chuyển đổi phép nhân thành phép cộng
    // a × b % c = [(a + a) % c] + [(a + a) % c] + ... [(a + a) % c] Cộng tổng số b a để tìm mô đun
    unsigned int res = 0;
    unsigned int a_temp = a;
    unsigned int b_temp = b;

    while (b_temp > 0)
    {
        if (b_temp & 1)
        {
            res = (res + a_temp) % c;
        }

        a_temp = (a_temp + a_temp) % c;

        b_temp >>= 1;
    }

    return res;
}

// Thuật toán Euclide mở rộng
// Các tham số và giá trị trả về:
// Dùng thuật toán Euclide tìm ước chung lớn nhất g của hai số a và b, a >= b
// Theo định lý Bezu, tồn tại nghiệm x và y cho a × x + b × y = g
// Sử dụng thuật toán Euclide mở rộng, tìm tập nghiệm x, y cho a × x + b × y = gcd
// Tập hợp nghiệm của x và y này sau đó được sử dụng để tìm nghịch đảo của phép nhân
unsigned int RSA::ExGcd(const unsigned int &a, const unsigned int &b, unsigned int &x, unsigned int &y)
{
    // Ý tưởng chung:
    //  Sử dụng thuật toán Euclide, tìm ước chung lớn nhất của a và b: gcd(a, b) = gcd(b, a % b)
    //  Vì vậy nó là một quá trình đệ quy, lối ra đệ quy là số bên phải b, tức là số bên phải a % b = 0.
    //     Lúc này số bên trái a là ước số chung lớn nhất và trả về
    //  Lúc này: gcd(g, 0) = g = a × x + b × y = a × 1 + b × 0
    //  Tức là ở đỉnh ngăn xếp đệ quy thu được nghiệm x = 1, y = 0
    //  Sau đó quay trở lại và thoát khỏi ngăn xếp đệ quy theo từng lớp, được suy ra bằng thuật toán Euclide mở rộng,
    //      cập nhật x và y theo từng lớp và cuối cùng thu được các giải pháp x và y

    // lối thoát đệ quy
    if (b == 0)
    {
        x = 1;
        y = 0;

        return a;
    }

    // logic đệ quy
    unsigned int g = ExGcd(b, a % b, x, y); // g là ước chung lớn nhất của đệ quy hiện tại

    // gợi ý:
    // Cập nhật x và y từ dưới cùng của ngăn xếp lên trên cùng của ngăn xếp, nghĩa là viết mã đệ quy logic theo hướng thuận.
    // Sau đó khi quay trở lại, nó được cập nhật từ đầu ngăn xếp xuống cuối ngăn xếp và cuối cùng thu được lời giải.
    int temp = y;
    y = x - (a / b) * y;
    x = temp;
    cout << "Uoc chung lon nhat !!!: " << g << endl;
    cout << "X: " << x << endl;
    cout << "Y: " << y << endl;
    return g; // Trả về ước chung lớn nhất
}

// Tìm nghịch đảo của phép nhân
// Tham số: a × x % b = 1 với a và b
// Giá trị trả về: phần tử nghịch đảo nhân x của modulo b
unsigned int RSA::GetMulInverse(const unsigned int &a, const unsigned int &b)
{
    //Ý tưởng chung:
    // Nếu tìm phần tử nghịch đảo x của a modulo b, tức là a × x % b = 1
    // Tức là công thức đồng dư: ax ≡ 1(mod b)
    // Có thể chuyển đổi thành phương trình vô định: a × x + b × y = 1

    // Với hai số nguyên tố a, b, ước chung lớn nhất là 1, tức là gcd(a, b) = 1
    // Vậy: a × x + b × y = 1 = gcd(a, b)
    // Theo định lý Bezu, tồn tại nghiệm x và y cho a × x + b × y = gcd(a, b)
    // Nghĩa là, cho a và b, giải tìm x

    // Vì thế:
    // Sử dụng thuật toán Euclide mở rộng để tìm nghiệm x của a × x + b × y = 1
    // Từ công thức đồng đẳng, phần tử nghịch đảo z=(x % b + b) % b

    unsigned int x = 0;
    unsigned int y = 0;
    // unsigned int g = this->ExGcd(a, b, x, y); // Sử dụng thuật toán Euclide mở rộng để tìm nghiệm x cho a × x + b × y = 1
    this->ExGcd(a, b, x, y); // Sử dụng thuật toán Euclide mở rộng để tìm nghiệm x cho a × x + b × y = 1
    x = (x % b + b) % b;
    // gợi ý:
    // x là nghịch đảo nhân của a modulo b, nhưng nó không đảm bảo là số dương và nằm trong (a, b) nên cần phải cập nhật.
    // Nhiều lời giải thích cho bước này rất mơ hồ.

    // Ý tưởng: Nếu x là số âm thì cần chuyển thành số dương, thuộc tính phép toán modulo đảm bảo kết quả không thay đổi.
    // Giả sử x = -9, b = 20
    // Thuộc tính của phép toán mô-đun: đối với số âm -9 ≡ -9 % 20 ≡ đối với số dương x1 % 20
    // Tìm cách chuyển số âm -9 thành số dương x1, đảm bảo kết quả modulo giống hệt nhau
    // Chuyển 20 thành số âm và thêm hệ số để tạo thành -9, tức là [20 × (-1) + 11] % 20 = -9
    // Thuộc tính của hoạt động mô-đun: -9 = -9 % 20= [20 × (-1) + 11] % 20 = {[(-20) % 20] + (11 % 20)} % 20 = [0 + (11 % 20)] % 20 = 11 % 20 = 11
    // Vậy x1 mới cập nhật là 11

    // x % b: giảm số âm về phạm vi (-b, 0]
    // Thêm 1 b có thể chuyển đổi nó thành số dương cùng một lúc, trong khoảng [0, b]
    // Lưu ý rằng nếu x % b = 0, +b = b, bạn cũng cần % b để làm cho phạm vi nằm trong [0, b)

    return x;
}

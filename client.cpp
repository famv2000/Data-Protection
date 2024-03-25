#include "rsa.h"
#include "client.h"
#include "ui_client.h"

Client::Client(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Client)
{
    ui->setupUi(this);
    this->setWindowTitle("RSA Клиент");

    connect(ui->btnGenerateNewRSAParameters, &QPushButton::clicked, this, &Client::clickBtnGenerateNewRSAParameters);
    connect(ui->btnReset, &QPushButton::clicked, this, &Client::clickBtnReset);
    connect(ui->btnSendPublicKey, &QPushButton::clicked,
            this, [=](){ emit Client::sendPublicKey(ui->le_public_e->text().toUInt(), ui->le_public_n->text().toUInt()); });
    connect(ui->btnDecrypt, &QPushButton::clicked, this, &Client::clickBtnDecrypt);
}

Client::~Client()
{
    delete ui;
}


void Client::clickBtnGenerateNewRSAParameters()
{
    RSA *rsa;
    string plaintext_str("abc");
    vector<unsigned int> ciphertext_int;
    QString plaintext_str1;

    do
    {
        rsa = new RSA;

        ciphertext_int = RSA::Encrypt(plaintext_str, rsa->e_arg_, rsa->n_arg_);
        plaintext_str1 = RSA::Decrypt(ciphertext_int, rsa->d_arg_, rsa->n_arg_);

    } while (plaintext_str != plaintext_str1.toStdString());

    ui->lb_p->setText(QString::number(rsa->p_arg_));
    ui->lb_q->setText(QString::number(rsa->q_arg_));
    ui->lb_e->setText(QString::number(rsa->e_arg_));
    ui->lb_d->setText(QString::number(rsa->d_arg_));
    ui->lb_n->setText(QString::number(rsa->n_arg_));
    ui->lb_fn->setText(QString::number(rsa->n_Euler_func_arg_));

    ui->le_privete_d->setText(QString::number(rsa->d_arg_));
    ui->le_privete_n->setText(QString::number(rsa->n_arg_));

    ui->le_public_e->setText(QString::number(rsa->e_arg_));
    ui->le_public_n->setText(QString::number(rsa->n_arg_));

    delete rsa;
}

void Client::clickBtnReset()
{
    ui->le_privete_d->setText(ui->lb_d->text());
    ui->le_privete_n->setText(ui->lb_n->text());
}

void Client::clickBtnDecrypt()
{
    if (0 == this->_ciphertext_int.size())
    {
        return;
    }

    QString plaintext_str1 = RSA::Decrypt(this->_ciphertext_int, ui->le_privete_d->text().toUInt(), ui->le_privete_n->text().toUInt());
    ui->tbExplicitText->clear();
    ui->tbExplicitText->append(plaintext_str1);
}

void Client::getCodedText(std::vector<unsigned int> ciphertext_int)
{
    this->_ciphertext_int = ciphertext_int;

    ui->tbCodedText->clear();
    QString str;
    for (unsigned int i : this->_ciphertext_int)
    {
        str.append(QString::number(i));
    }
    ui->tbCodedText->append(str);
}

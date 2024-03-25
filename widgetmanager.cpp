#include "widgetmanager.h"
#include "client.h"
#include "server.h"

WidgetManager::WidgetManager(QObject *parent)
    : QObject{parent}
{
    Client* client = new Client;
    Server* server = new Server;

    /* Sử dụng trình quản lý cửa sổ để quản lý tín hiệu giữa Máy khách và Máy chủ */
    connect(client, &Client::sendPublicKey, server, &Server::setPublicKey);
    connect(server, &Server::sendCodedText, client, &Client::getCodedText);

    client->show();
    server->show();
}

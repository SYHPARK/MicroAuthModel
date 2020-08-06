#include <iostream>
#include <QCoreApplication>
#include "net.h"

//#include <QtNetwork/QNetworkRequest>
//#include <QtNetwork/QNetworkCookie>
#include <QtNetwork>
using namespace std;

void Net::replyFinished(QNetworkReply* reply){
    qDebug() << reply->readAll();
    auto cookieVar = reply->header(QNetworkRequest::SetCookieHeader);
    qDebug() << cookieVar;
    qDebug() << cookieVar.isValid();
    qDebug() << cookieVar.Size;
    if (cookieVar.isValid()) {
        QList<QNetworkCookie> cookies = cookieVar.value<QList<QNetworkCookie> >();
        for(int i=0; i<cookies.size(); i++)
            qDebug() << cookies.at(i).toRawForm();
    }
    //QString mime = reply->header(QNetworkRequest::ContentTypeHeader).toString();
    //printf("%s\n", mime);
}

void Net::CheckSite(QString url){
    QUrl qrl(url);
    manager = new QNetworkAccessManager(this);

    QString auth = "i_don_know";

    //User: dXNlcjp1c2Vy
    //Manager: bWFuYWdlcjptYW5hZ2Vy
    QByteArray data = auth.toLocal8Bit().toBase64();
    QString headerData = "Basic " + data;

    connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinished(QNetworkReply*)));
    QNetworkRequest request = QNetworkRequest(QUrl(qrl));
    request.setRawHeader("Authorization", headerData.toLocal8Bit());

    //QString token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b25nYmFrIiwiZXhwIjoxNTk2NzA4NzkwLjQwMTQ5MSwiaWF0IjoxNTk2NzA1MTkwLjQwMTQ5MSwibGV2ZWwiOiJzdXBlcnZpc29yIn0.gWNeFUTqFwKZKD2BYI99orNvHsJy20cYS6jdDDhmUx0";

//Wrong Token
    //QString token = "abcd.efgh.ijkl";

//Expired Token
    QString token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b25nYmFrIiwiZXhwIjoxNTk2NTIxODEzLjk1MDc4MywiaWF0IjoxNTk2NTE4MjEzLjk1MDc4MywibGV2ZWwiOiJ1c2VyIn0.lKUb9BkveeR2U_b4hz-4SrVpHqxkIWkGs92IWg7qbt4";

    request.setRawHeader("JSONToken", token.toLocal8Bit());

    auto reply = manager->get(request);

    //request.setRawHeader("Content-Type", "text/html; charset=utf-8");
    //auto reply = manager->post(request, token);
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Net handler;
    handler.CheckSite("http://192.168.32.130:8888");

    return a.exec();
}

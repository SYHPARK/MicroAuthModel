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
    //QByteArray token = "{\"name\":\"yongbak\"}";
    //QByteArray postDataSize = QByteArray::number(token.size());

    QString auth = "i_don:know";//"user:user";
    QByteArray data = auth.toLocal8Bit().toBase64();
    QString headerData = "Basic " + data;

    connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinished(QNetworkReply*)));
    QNetworkRequest request = QNetworkRequest(QUrl(qrl));
    request.setRawHeader("Authorization", headerData.toLocal8Bit());
//Wrong Token
    //QString token = "abcd.efgh.ijkl";
//User Token
    QString token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b25nYmFrIiwiZXhwIjoxNTk2NTIxODEzLjk1MDc4MywiaWF0IjoxNTk2NTE4MjEzLjk1MDc4MywibGV2ZWwiOiJ1c2VyIn0.lKUb9BkveeR2U_b4hz-4SrVpHqxkIWkGs92IWg7qbt4";
//Supervisor Token
    //QString token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b25nYmFrIiwiZXhwIjoxNTk2NTIwNjY4LjMwODk2MTYsImlhdCI6MTU5NjUxNzA2OC4zMDg5NjE2LCJsZXZlbCI6InN1cGVydmlzb3IifQ.LozdeP7kze01pHtcLa7a2QuXRy-wLrOEQ-DHRcW180I";
    request.setRawHeader("JSONToken", token.toLocal8Bit());
    auto reply = manager->get(request);

    //request.setRawHeader("Content-Type", "text/html; charset=utf-8");
    //auto reply = manager->post(request, token);

    //QVariant attr = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);

    //QList<QByteArray> headerList = reply->rawHeaderList();
    //int a=12;
    //printf("%d", headerList[0]);
    //printf("\n%d\n", reply->hasRawHeader("Content-Length"));
    //cout<<reply->attribute("JWT");

}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Net handler;
    handler.CheckSite("http://192.168.32.130:8888");

    return a.exec();
}

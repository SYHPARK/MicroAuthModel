#ifndef NET_H
#define NET_H

#include <QObject>
#include <QtCore>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

class Net: public QObject{
Q_OBJECT
    QNetworkAccessManager* manager;
private slots:
    void replyFinished(QNetworkReply*);
public:
    void CheckSite(QString url);
};


#endif // NET_H

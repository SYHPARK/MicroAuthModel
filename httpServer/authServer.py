# sudo pip3 uninstall JWT
# sudo pip3 install PyJWT (https://pyjwt.readthedocs.io/en/latest/)
import jwt
import time
import socket

IP = '127.0.0.1'
PORT = 5432
SIZE = 10240
ADDR = (IP, PORT)

key = "yangDongHYEON!!#"

# 서버 소켓 설정
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind(ADDR)  # 주소 바인딩
    server_socket.listen()  # 클라이언트의 요청을 받을 준비

    # 무한루프 진입
    while True:
        client_socket, client_addr = server_socket.accept()  # 수신대기, 접속한 클라이언트 정보 (소켓, 주소) 반환
        msg = client_socket.recv(SIZE)  # 클라이언트가 보낸 메시지 반환
        print("[{}] message : {}".format(client_addr,msg))  # 클라이언트가 보낸 메시지 출력
        print(len(msg))

        if len(msg) == 1:               #createToken
            currentTime = time.time()
            payload = {"iss": "yongbak", "exp": currentTime+3600, "iat": currentTime}
            if msg.decode()[0] == '\x02':
                payload["level"] = "guest"
            elif msg.decode()[0] == '\x03':
                payload["level"] = "user" 
            elif msg.decode()[0] == '\x04':
                payload["level"] = "manager"
            elif msg.decode()[0] == '\x05':
                payload["level"] = "supervisor"
            token = jwt.encode(payload, key, algorithm = "HS256")
            print("Issued Token: %s\n"%token)
            print("Token Decoded: %s\n"%jwt.decode(token, key, algorithm = "HS256"))
            print(type(token))
            client_socket.sendall(token)  # 클라이언트에게 응답
        else:				#verityToken
            print(msg)
            print(type(msg))
            level = '\x20'
            try:
                decodedToken = jwt.decode(msg.decode(), key, algorithm = "HS256")
                if decodedToken["level"] == 'guest':
                    level = '\x02'
                elif decodedToken["level"] == 'user':
                    level = '\x03'
                elif decodedToken["level"] == 'manager':
                    level = '\x04'
                elif decodedToken["level"] == 'supervisor':
                    level = '\x05'
            except jwt.ExpiredSignatureError:
                print("This token is expired!")
                level = '\x10'
#            except jwt.ValueError:
#                print("Value Error!")
#                pass
            except Exception:
                print("Except!")
                pass
            client_socket.sendall(level.encode())	#decode, token processing
#            print(jwt.decode(msg.decode(), key, algorithm = "HS256")["level"])
#            print(jwt.decode(msg.decode(), key, algorithm = "HS256"))

        client_socket.close()  # 클라이언트 소켓 종료

'''
PRIVATE_KEY_ID_FROM_JSON ="e1eba38c4d7fef671273a6f62c46cbb15db3f854"
PRIVATE_KEY_FROM_JSON= "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCQvQNoYwOz6sHO\nfPHVVVM+5qXJKvSq/OBcuom8L58O0SN5rgNeGGINHuegrTtTMoC6xgk6nvcuq9uh\noQy4gy2Rzqj+3fKRR3J94NO3gYXyILz1Uj5mzqEDJ0xyFMEfUQXkuRm9G8Y0EweR\noiQyA0sSRtegZLJInu9ELDVHqegjQsztaYjh9amjI9i5DeRQCOiTiYTfsk1Ecg1J\nqCHy3GiquHuuttFQe+HEKTuLAZQtSTd10u6aIlJ1Dxu1sj3aol1i2OfHPAoFvnx/\nbRIgJlDWzUJ2x664rVquqLDhkIw+2GrmV4DtNJujITjZnZt2ojlrCo4GMRzd7qAm\nCYtF+QZdAgMBAAECggEAOHvCwjBtx/8zvejNmWLQd0ocZZqhW78OsbFMQgfVizs7\nnGc3wjdCwHsQiohAEBIz4W+aN2nE7c48imFmrPToSi/7jGbCHEblG9Gq3cCqrJhx\nFU2Qs58sf6YM87I8wYNliOJhdIbLvRO2DvPXKztUxx+lU18ooiWAGzsjWcGpKWT4\nagxYGmlimmSme2OuIA9Qw1z9tloeNB8hgAN8CDWpT9VlBwfbiLWeDokf6sMAhJ/+\nbWEK+NTvY+GBHb+/VSiB4rhPOpmV5gtKmgvngeEvYGV8HYAojFObuhHMepAVeoPe\nGUhhStJNxrFn3lrnuoPFkL/L/QZreMZSuAIrufDT8wKBgQDH7ZSAUaAPiUKzJiYI\ndgOvblywKfC0Snjvqm/w+oHdFoEuTjwVZ5NyFkJQny53sd0ANLLkwJtklGe8zMKv\nJBQAzKK0hyvfekv9hcn+VlURrAPkb/xn+Jq25VhM3ukRs56wbBLIV1VJ3uL26VIx\nkhjE4a1DpBxL0q8auYLJH9PihwKBgQC5VO0PV72GuYosvs0T+RNiMA2QsktshYIg\nKG5T4Gip3O21TVUOrF+eHgHrQfU4mk6hyumNhaCxD6oyz2cXT03LYCINKin+9OqR\nx558xBcH7a87bv78QQ9H8lupNT3zyK0Egw/jxQ55OrhCOzfy/V7mEKUv3pn1gwt5\n+DswUDW0+wKBgQDHKMdm8GkXMO/t0JHQmedf6fuRTaZHo2xHqywqDRIysIltHGhE\nFlLOMphLAddjSx5RZy3SLIBfuGqCrCNAHxuCFFf8qC6vR3/NhGpM36mMmiOie2Ag\nHonYqizFHsVkad8p9e7b/gurM8o6lwDW+qeL8RgNqry5V54xbB15xyfmnwKBgEdB\n3fveMmLQh834doVNaSSBcVXHF7TcCFIw+WqKh/N3nHXvC9seb40t4HMB4zUmL0GJ\n8Q6W6Ffru/bZQ7v0o+akSbNiGM+Mf3wZklhKVMiZnJxvat62bReumYuPiwhmig+I\nDN34cD4wU5QzjKmCvbAbikfDgNKi1hDJXoiO7ndtAoGBALauTA1J3Xg7Duoe/iFJ\nmFkgY4qbYjrkOlmTIumqAJ6j3CbUyiMCA4NBqXq36bDsxsvnGMeeTlsnR1ZfZ+oq\n/dB8oAwIBxMBPUjprzyRv/UYpDa85Zhbi2o2jC48z1h6+ETrFbNffkxdreMwm/TD\nUSnDktVvKZ+w01kk4EcMKWPm\n-----END PRIVATE KEY-----\n"


def getSignedJWT():
    iat = time.time()
    exp = iat + 3600
    payload = { 'iss': 'kibua20-service@calendarapi-282612.iam.gserviceaccount.com', 'scope': 'https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar.events.readonly', 'aud':'https://oauth2.googleapis.com/token', 'iat': iat, 'exp': exp }
    additional_headers = {'kid': PRIVATE_KEY_ID_FROM_JSON}
    signed_jwt = jwt.encode(payload, PRIVATE_KEY_FROM_JSON, headers=additional_headers, algorithm='HS256')
    return signed_jwt#.decode('utf8')


key="hi"
encoded = jwt.encode({'some': 'payload', 'iat': time.time(), 'exp': time.time()+3600 }, key, algorithm='HS256')
print(encoded)
decoded = jwt.decode(encoded, key, algorithms='HS256')
print(decoded)

encoded = jwt.encode({ 'iat': time.time(), 'exp': time.time()+3600 }, PRIVATE_KEY_FROM_JSON, algorithm="HS256")
print(encoded)
decoded = jwt.decode(encoded, PRIVATE_KEY_FROM_JSON, algorithms="HS256")
print(decoded)

encoded = getSignedJWT()
print(encoded)
#print(jwt.decode(encoded, PRIVATE_KEY_FROM_JSON, algorithm="HS256"))
'''

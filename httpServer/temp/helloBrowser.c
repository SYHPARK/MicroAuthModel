#include <stdio.h>
#include <microhttpd.h>
#include <json.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#define DEFAULT_PAGE "<html><head><title>YONGBAK test</title></head><body>Hello, browser!</body></html>"
#define PORT 8888

/*------ Base64 Encoding Table ------*/
static const char MimeBase64[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};
/*------ Base64 Decoding Table ------*/
static int DecodeMimeBase64[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
 };

int base64_decode(char *text, int numBytes, unsigned char **dec)
{
  *dec = (unsigned char*)malloc(sizeof(unsigned char)*numBytes);
  memset(*dec, 0, numBytes);
  unsigned char* dst = *dec;
  const char* cp;
  int space_idx = 0, phase;
  int d, prev_d = 0;
  unsigned char c;
    space_idx = 0;
    phase = 0;
    for ( cp = text; *cp != '\0'; ++cp ) {
        d = DecodeMimeBase64[(int) *cp];
        if ( d != -1 ) {
            switch ( phase ) {
                case 0:
                    ++phase;
                    break;
                case 1:
                    c = ( ( prev_d << 2 ) | ( ( d & 0x30 ) >> 4 ) );
                    if ( space_idx < numBytes )
                        dst[space_idx++] = c;
                    ++phase;
                    break;
                case 2:
                    c = ( ( ( prev_d & 0xf ) << 4 ) | ( ( d & 0x3c ) >> 2 ) );
                    if ( space_idx < numBytes )
                        dst[space_idx++] = c;
                    ++phase;
                    break;
                case 3:
                    c = ( ( ( prev_d & 0x03 ) << 6 ) | d );
                    if ( space_idx < numBytes )
                        dst[space_idx++] = c;
                    phase = 0;
                    break;
            }
            prev_d = d;
        }
    }
    return space_idx;
}
int base64_encode(char *text, int numBytes, char **encodedText)
{
  unsigned char input[3]  = {0,0,0};
  unsigned char output[4] = {0,0,0,0};
  int   index, i, j, size;
  char *p, *plen;
  plen           = text + numBytes - 1;
  size           = (4 * (numBytes / 3)) + (numBytes % 3? 4 : 0) + 1;
  (*encodedText) = (char*)malloc(size);
  j              = 0;
    for  (i = 0, p = text;p <= plen; i++, p++) {
        index = i % 3;
        input[index] = *p;
        if (index == 2 || p == plen) {
            output[0] = ((input[0] & 0xFC) >> 2);
            output[1] = ((input[0] & 0x3) << 4) | ((input[1] & 0xF0) >> 4);
            output[2] = ((input[1] & 0xF) << 2) | ((input[2] & 0xC0) >> 6);
            output[3] = (input[2] & 0x3F);
            (*encodedText)[j++] = MimeBase64[output[0]];
            (*encodedText)[j++] = MimeBase64[output[1]];
            (*encodedText)[j++] = index == 0? '=' : MimeBase64[output[2]];
            (*encodedText)[j++] = index <  2? '=' : MimeBase64[output[3]];
            input[0] = input[1] = input[2] = 0;
        }
    }
    for(; (*encodedText)[j-1]=='='; j--);
    (*encodedText)[j] = '\0';
    return size;
}

char* createToken(int auth){			//switch case depending on auth level
  json_object *jwt, *header, *payload, *secret;
  
  header = json_object_new_object();
  json_object_object_add(header, "typ", json_object_new_string("JWT"));
  json_object_object_add(header, "alg", json_object_new_string("HS256"));

  payload = json_object_new_object();
  unsigned long t = time(NULL);
  json_object_object_add(payload, "iss", json_object_new_string("yongbak"));
  json_object_object_add(payload, "exp", json_object_new_int(t + 3600));
  json_object_object_add(payload, "iat", json_object_new_int(t));
  json_object_object_add(payload, "level", json_object_new_string("supervisor"));
  json_object_object_add(payload, "power", json_object_new_int(1|2|4));

  jwt = json_object_new_object();
  json_object_object_add(jwt, "header", header);
  json_object_object_add(jwt, "payload", payload);

  printf("%s\n", json_object_to_json_string(jwt));

  char* encodedHeader;
  base64_encode(json_object_to_json_string(header), strlen(json_object_to_json_string(header)), &encodedHeader);

  unsigned char* decodedHeader;
  base64_decode(encodedHeader, strlen(encodedHeader), &decodedHeader);

  //printf("header base64: %s\n", encodedHeader);
  //printf("header base64_decode: %s\n", decodedHeader);

  if(strcmp(decodedHeader, json_object_to_json_string(header)))
	  printf("Base64 header encoding fail\n");

  char* encodedPayload;
  base64_encode(json_object_to_json_string(payload), strlen(json_object_to_json_string(payload)), &encodedPayload);

  unsigned char* decodedPayload;
  int idx = base64_decode(encodedPayload, strlen(encodedPayload), &decodedPayload);
  //printf("numBytes: %d\tidx: %d\n", strlen(encodedPayload), idx);
  decodedPayload[idx] = 0;

  printf("Original payload: %s\n",  json_object_to_json_string(payload));
  printf("Decoded payload: %s\n", decodedPayload);
  if(strcmp(decodedPayload, json_object_to_json_string(payload)))
	  printf("Base64 payload encoding fail\n");

  //printf("base64 header size: %d\n", sizeof(encodedHeader));
  //printf("base64 payload size: %d\n", sizeof(encodedPayload));
  
  char* jsonToken = (char*)malloc(strlen(encodedHeader) + strlen(encodedPayload) + 2);
  memset(jsonToken, 0, strlen(encodedHeader) + strlen(encodedPayload) + 2);

  strcpy(jsonToken, encodedHeader);
  //printf("After copy encodedHeader: %s\n", jsonToken);
  jsonToken[strlen(encodedHeader)] = '.';
  //printf("After add dot: %s\n", jsonToken);
  strcpy(jsonToken + strlen(encodedHeader) + 1, encodedPayload);
  //printf("After copy encodedPayload: %s\n", jsonToken);

  free(header);
  free(payload);
  free(jwt);
  free(encodedHeader);
  free(decodedHeader);
  free(encodedPayload);
  free(decodedPayload);
  return jsonToken;
}

int answer_to_connection (void *cls, struct MHD_Connection *connection, 
                          const char *url, 
                          const char *method, const char *version, 
                          const char *upload_data, 
                          size_t *upload_data_size, void **con_cls)
{
  char* auth = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "auth");
  if(!auth){
    fprintf(stdout, "No auth info!\n");
    return -1;
  }
  char page[300];
  sprintf(page,  "<html><head><title>YONGBAK test</title></head><body>Hello, browser %d!</body></html>", atoi(auth));

  //fprintf(stdout, "%d\n\n", atoi(auth));
  struct MHD_Response *response;
  int ret;

  char* token = createToken(1);
  printf("Encoded token: %s\n", token);

//  response = MHD_create_response_from_buffer (strlen(page),
//                                            (void* const) page, MHD_RESPMEM_PERSISTENT);
  response = MHD_create_response_from_buffer (strlen (DEFAULT_PAGE),
                                            (void*) DEFAULT_PAGE, MHD_RESPMEM_PERSISTENT);

//  MHD_add_response_header(response, "Cookie", token);

  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}

int main ()
{
  struct MHD_Daemon *daemon;
/*
  json_object *jwt, *header, *payload, *secret;
  
  header = json_object_new_object();
  json_object_object_add(header, "typ", json_object_new_string("JWT"));
  json_object_object_add(header, "alg", json_object_new_string("HS256"));

  payload = json_object_new_object();
  unsigned long t = time(NULL);
  json_object_object_add(payload, "iss", json_object_new_string("yongbak"));
  json_object_object_add(payload, "exp", json_object_new_int(t + 3600));
  json_object_object_add(payload, "iat", json_object_new_int(t));
  json_object_object_add(payload, "level", json_object_new_string("supervisor"));
  json_object_object_add(payload, "power", json_object_new_int(1|2|4));

  jwt = json_object_new_object();
  json_object_object_add(jwt, "header", header);
  json_object_object_add(jwt, "payload", payload);
  
  //json_object_object_add(header, "level", json_object_new_int(1));
  printf("%s\n", json_object_to_json_string(jwt));

  char* encodedHeader;
  base64_encode(json_object_to_json_string(header), strlen(json_object_to_json_string(header)), &encodedHeader);

  unsigned char* decodedHeader;
  base64_decode(encodedHeader, strlen(encodedHeader), &decodedHeader);

  printf("header base64: %s\n", encodedHeader);
  printf("header base64_decode: %s\n", decodedHeader);
*/
  daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL, 
                             &answer_to_connection, NULL, MHD_OPTION_END);
  if (NULL == daemon) return 1;
  getchar (); 

  MHD_stop_daemon (daemon);
  return 0;
}

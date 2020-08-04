#include <sys/types.h>
#ifndef _WIN32
#include <sys/select.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif
#include <microhttpd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <json.h>
#define PORT 8888

#define REALM     "\"Level Info\""
#define GUEST	"guest"
#define GUESTPW	"guest"
#define USER	"user"
#define USERPW	"user"
#define MANAGER	"manager"
#define MANAGERPW	"manager"
#define SUPERVISOR	"supervisor"
#define SUPERVISORPW	"supervisor"
#define GUESTPAGE	"<html><body>A guest.</body></html>"
#define USERPAGE	"<html><body>A user.</body></html>"
#define MANAGERPAGE	"<html><body>A manager.</body></html>"
#define SUPERVISORPAGE	"<html><body>A supervisor.</body></html>"

#define SERVERKEYFILE "server.key"
#define SERVERCERTFILE "server.pem"

enum level{ guest=0, user=1, manager=2, supervisor=3};

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

static char *
string_to_base64 (const char *message)
{
  const char *lookup =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  unsigned long l;
  size_t i;
  char *tmp;
  size_t length = strlen (message);

  tmp = malloc (length * 2 + 1);
  if (NULL == tmp)
    return NULL;
  tmp[0] = 0;
  for (i = 0; i < length; i += 3)
  {
    l = (((unsigned long) message[i]) << 16)
        | (((i + 1) < length) ? (((unsigned long) message[i + 1]) << 8) : 0)
        | (((i + 2) < length) ? ((unsigned long) message[i + 2]) : 0);


    strncat (tmp, &lookup[(l >> 18) & 0x3F], 1);
    strncat (tmp, &lookup[(l >> 12) & 0x3F], 1);

    if (i + 1 < length)
      strncat (tmp, &lookup[(l >> 6) & 0x3F], 1);
    if (i + 2 < length)
      strncat (tmp, &lookup[l & 0x3F], 1);
  }

  if (length % 3)
    strncat (tmp, "===", 3 - length % 3);

  return tmp;
}


static long
get_file_size (const char *filename)
{
  FILE *fp;

  fp = fopen (filename, "rb");
  if (fp)
  {
    long size;

    if ((0 != fseek (fp, 0, SEEK_END)) || (-1 == (size = ftell (fp))))
      size = 0;

    fclose (fp);

    return size;
  }
  else
    return 0;
}


static char *
load_file (const char *filename)
{
  FILE *fp;
  char *buffer;
  long size;

  size = get_file_size (filename);
  if (0 == size)
    return NULL;

  fp = fopen (filename, "rb");
  if (! fp)
    return NULL;

  buffer = malloc (size + 1);
  if (! buffer)
  {
    fclose (fp);
    return NULL;
  }
  buffer[size] = '\0';

  if (size != (long) fread (buffer, 1, size, fp))
  {
    free (buffer);
    buffer = NULL;
  }

  fclose (fp);
  return buffer;
}


static int
ask_for_authentication (struct MHD_Connection *connection, const char *realm)
{
  printf("[*] ask_for_authenticatioin start\n");
  int ret;
  struct MHD_Response *response;
  char *headervalue;
  size_t slen;
  const char *strbase = "Basic realm=";

  response = MHD_create_response_from_buffer (0, NULL,
                                              MHD_RESPMEM_PERSISTENT);
  if (! response)
    return MHD_NO;

  slen = strlen (strbase) + strlen (realm) + 1;
  if (NULL == (headervalue = malloc (slen)))
    return MHD_NO;
  snprintf (headervalue,
            slen,
            "%s%s",
            strbase,
            realm);
  ret = MHD_add_response_header (response,
                                 "WWW-Authenticate",
                                 headervalue);
  free (headervalue);
  if (! ret)
  {
    MHD_destroy_response (response);
    return MHD_NO;
  }

  ret = MHD_queue_response (connection,
                            MHD_HTTP_UNAUTHORIZED,
                            response);
  MHD_destroy_response (response);
  printf("[*] ask_for_authentication end\n");
  return ret;
}


static int
is_authenticated (struct MHD_Connection *connection,
                  const char *username,
                  const char *password)
{
  printf("[*] is_authenticated start\n");
  const char *headervalue;
  char *expected_b64;
  char *expected;
  const char *strbase = "Basic ";
  int authenticated;
  size_t slen;

  headervalue =
    MHD_lookup_connection_value (connection, MHD_HEADER_KIND,
                                 "Authorization");
  if (NULL == headervalue)
    return 0;
  if (0 != strncmp (headervalue, strbase, strlen (strbase)))
    return 0;

  slen = strlen (username) + 1 + strlen (password) + 1;
  if (NULL == (expected = malloc (slen)))
    return 0;
  snprintf (expected,
            slen,
            "%s:%s",
            username,
            password);
  expected_b64 = string_to_base64 (expected);
  free (expected);
  if (NULL == expected_b64)
    return 0;

  authenticated =
    (strcmp (headervalue + strlen (strbase), expected_b64) == 0);
  free (expected_b64);
  printf("[*] is_authenticated end\n");
  return authenticated;
}


static int
secret_page (struct MHD_Connection *connection, enum level l)
{
  printf("[*] start secret page\n");
  int ret;
  struct MHD_Response *response;
  const char* page;
  switch(l){
    case guest:
      page = GUESTPAGE;
      break;
    case user:
      page = USERPAGE;
      break;
    case manager:
      page = MANAGERPAGE;
      break;
    case supervisor:
      page = SUPERVISORPAGE;
      break;
    default:
      page = "<html><body>Error</body></html>";
  }
  //const char *page = "<html><body>A secret.</body></html>";

  response =
    MHD_create_response_from_buffer (strlen (page), (void *) page,
                                     MHD_RESPMEM_PERSISTENT);

  char* token = createToken(l);
  printf("Encoded token: %s\n", token);

  if (! response)
    return MHD_NO;

  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}


static int 
answer_to_connection (void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **con_cls)
{
  printf("[*] answer to connection start\n");
  (void) cls;               /* Unused. Silent compiler warning. */
  (void) url;               /* Unused. Silent compiler warning. */
  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (0 != strcmp (method, "GET"))
    return MHD_NO;
  if (NULL == *con_cls)
  {
    *con_cls = connection;
    return MHD_YES;
  }
  printf("[*] in answer_to_connection\n");
  enum level l = guest;
  if(is_authenticated(connection, GUEST, GUESTPW));
  else if(is_authenticated(connection, USER, USERPW)) l = user;
  else if(is_authenticated(connection, MANAGER, MANAGERPW)) l = manager;
  else if(is_authenticated(connection, SUPERVISOR, SUPERVISORPW)) l = supervisor;
  else return ask_for_authentication(connection, REALM);
  //if (! is_authenticated (connection, USER, PASSWORD))
  //  return ask_for_authentication (connection, REALM);
  printf("[*] before secret page\n");
  return secret_page (connection, l);
}


int
main ()
{
  struct MHD_Daemon *daemon;
  char *key_pem;
  char *cert_pem;
/*
  key_pem = load_file (SERVERKEYFILE);
  cert_pem = load_file (SERVERCERTFILE);

  if ((key_pem == NULL) || (cert_pem == NULL))
  {
    printf ("The key/certificate files could not be read.\n");
    if (NULL != key_pem)
      free (key_pem);
    if (NULL != cert_pem)
      free (cert_pem);
    return 1;
  }
*/
  printf("[*] before daemon\n");
  daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
		  		&answer_to_connection, NULL, MHD_OPTION_END);
  printf("[*] end daemon\n");
//  daemon =
//    MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS, PORT, NULL,
//                      NULL, &answer_to_connection, NULL, MHD_OPTION_END);
//                      MHD_OPTION_HTTPS_MEM_KEY, key_pem,
//                      MHD_OPTION_HTTPS_MEM_CERT, cert_pem, MHD_OPTION_END);
//  if (NULL == daemon)
//  {
//    printf ("Error with this key and pem\n");
//    printf ("%s\n", cert_pem);

//    free (key_pem);
//    free (cert_pem);

//    return 1;
//  }

  (void) getchar ();

  MHD_stop_daemon (daemon);
  free (key_pem);
  free (cert_pem);

  return 0;
}


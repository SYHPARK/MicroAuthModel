/**
 * Compile with
 * gcc -o test_iddawc test_iddawc.c -liddawc
 */
#include <stdio.h>
#include <iddawc.h>

int main() {
  struct _i_session i_session;
  char redirect_to[4100] = {0};
  i_init_session(&i_session);
  i_set_parameter_list(&i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_ID_TOKEN|I_RESPONSE_TYPE_CODE,
                                   I_OPT_OPENID_CONFIG_ENDPOINT, "http://127.0.0.1:8888",
                                   I_OPT_CLIENT_ID, "client1",
                                   I_OPT_CLIENT_SECRET, "mySecret",
                                   I_OPT_REDIRECT_URI, "https://www.naver.com",
                                   I_OPT_SCOPE, "openid",
                                   I_OPT_STATE_GENERATE, 16,
                                   I_OPT_NONCE_GENERATE, 32,
                                   I_OPT_NONE);
  if (i_load_openid_config(&i_session)) {
    fprintf(stderr, "Error loading openid-configuration\n");
    i_clean_session(&i_session);
    return 1;
  }

  // First step: get redirection to login page
  if (i_build_auth_url_get(&i_session)) {
    fprintf(stderr, "Error building auth request\n");
    i_clean_session(&i_session);
    return 1;
  }
  printf("Redirect to: %s\n", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));

  // When the user has logged in the external application, gets redirected with a result, we parse the result
  fprintf(stdout, "Enter redirect URL\n");
  fgets(redirect_to, 4096, stdin);
  redirect_to[strlen(redirect_to)-1] = '\0';
  i_set_str_parameter(&i_session, I_OPT_REDIRECT_TO, redirect_to);
  if (i_parse_redirect_to(&i_session) != I_OK) {
    fprintf(stderr, "Error parsing redirect_to url\n");
    i_clean_session(&i_session);
    return 1;
  }

  // Run the token request, get the refresh and access tokens
  if (i_run_token_request(&i_session) != I_OK) {
    fprintf(stderr, "Error running token request\n");
    i_clean_session(&i_session);
    return 1;
  }
  
  // And finally we load user info using the access token
  if (i_load_userinfo(&i_session) != I_OK) {
    fprintf(stderr, "Error loading userinfo\n");
    i_clean_session(&i_session);
    return 1;
  }

  fprintf(stdout, "userinfo:\n%s\n", i_get_str_parameter(&i_session, I_OPT_USERINFO));
  
  // Cleanup session
  i_clean_session(&i_session);

  return 0;
}

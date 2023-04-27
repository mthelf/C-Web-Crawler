// This program reads in a list of URLs from a file specified as a command-line argument. It then creates a thread for each URL and passes the URL as an argument to the fetch_url function. The fetch_url function uses libcurl to fetch the contents of the URL. After all threads have completed, the program exits.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <pthread.h>

#define MAX_URLS 1000
#define MAX_BUF_SIZE 1024

char urls[MAX_URLS][MAX_BUF_SIZE];
int num_urls = 0;
int curr_url = 0;

void *fetch_url(void *arg) {
  char *url = (char *)arg;
  CURL *curl = curl_easy_init();

  if (curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
  }

  pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
  FILE *fp;
  char line[MAX_BUF_SIZE];
  pthread_t threads[MAX_URLS];

  if (argc != 2) {
    fprintf(stderr, "usage: %s <url file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  fp = fopen(argv[1], "r");
  if (!fp) {
    perror("Failed to open file");
    exit(EXIT_FAILURE);
  }

  while (fgets(line, MAX_BUF_SIZE, fp)) {
    // remove newline character
    line[strcspn(line, "\n")] = 0;
    strncpy(urls[num_urls], line, MAX_BUF_SIZE);
    num_urls++;
  }

  fclose(fp);

  while (curr_url < num_urls) {
    pthread_create(&threads[curr_url], NULL, fetch_url, urls[curr_url]);
    curr_url++;
  }

  for (int i = 0; i < num_urls; i++) {
    pthread_join(threads[i], NULL);
  }

  exit(EXIT_SUCCESS);
}



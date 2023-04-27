/*
Michael Helf
Ahtsham Sohail
Shahpur Khan

50:198:341 Operating Systems - Spring 2023
Group Project: Multithreaded Web Crawler


*/

// Set our caps for request count, link count, etc.
int max_con = 200;
int max_total = 200;
int max_requests = 50;
int max_link_per_page = 5;
int follow_relative_links = 0;

// Libxml is a C library for data manipulation.

// Relevant to this, we will include its HTML parser,
#include <libxml/HTMLparser.h>
// the XPath language for doc addressing purposes,
#include <libxml/xpath.h>
// and the library of generic Resource Identification routines.
#include <libxml/uri.h>
// We will also include...
// curl, a URL-focused data transferring tool,
#include <curl/curl.h>
// Standard library for utility functions

#include <stdlib.h>
// String library for string manipulation etc

#include <string.h>
// Math library to use mathematical functions

#include <math.h>

#include <pthread.h>
// And include signal.h (specifies signal-handling during execution)
#include <signal.h>

// Set a cap on URL length to minimize impacts to performance
#define MAX_URL_LENGTH 1500
#define MAX_URLS 1000
#define RED "\x1b[31m"
#define NORMAL "\x1b[m"
#define GREEN "\x1b[32m"

// Initialize pending interrupt with value zero
int pending_interrupt = 0;
// Sighandler should have no return value

void sighandler(int dummy)
{    // Now, set it to 1

  pending_interrupt = 1;
}

/* resizable buffer */
typedef struct {
  char *buf;
  size_t size;
} memory;


/*The function first calculates the total size of the response data in bytes using sz and nmemb. It then casts the ctx pointer to a memory
pointer and uses realloc to allocate memory for the response data in the buf field of the memory structure. If the realloc call fails
the function prints an error message and returns 0.

If the realloc call succeeds, the function copies the response data to the end of the buf field using memcpy and updates the size
field of the memory structure to reflect the new size of the buffer. Finally, the function returns the total size of the response data in bytes. */
size_t grow_buffer(void *contents, size_t sz, size_t nmemb, void *ctx)
{
  size_t realsize = sz * nmemb;
  memory *mem = (memory*) ctx;
  char *ptr = realloc(mem->buf, mem->size + realsize);
  if(!ptr) {
    /* out of memory */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  mem->buf = ptr;
  memcpy(&(mem->buf[mem->size]), contents, realsize);
  mem->size += realsize;
  return realsize;
}

// Make handle with URL arg
CURL *make_handle(char *url)
{    // curl_easy_init returns an easy handle (to be inputted to other easy functions)

  CURL *handle = curl_easy_init();

  /* Important: use HTTP2 over HTTPS */
  curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(handle, CURLOPT_URL, url);

  /* buffer body */
  memory *mem = malloc(sizeof(memory));
  mem->size = 0;
  mem->buf = malloc(1);
  /*write the response data from an HTTP request to a dynamically growing memory buffer using a callback function called grow_buffer.
  The CURLOPT_WRITEFUNCTION option specifies the callback function that will be used to handle the incoming data, which in this case is grow_buffer.
  The CURLOPT_WRITEDATA option specifies the pointer to the memory buffer where the data will be stored, which is mem.
  The CURLOPT_PRIVATE option sets a private pointer associated with this handle to mem.
  This private pointer can be used later to retrieve the data buffer associated with this handle. */
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, grow_buffer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, mem);
  curl_easy_setopt(handle, CURLOPT_PRIVATE, mem);

  /* For completeness, handles all the possible errors when loading a webpage */


  /* sets the value of the Accept-Encoding HTTP header to an empty string, indicating that the client accepts any encoding. */
  curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");

  /* sets the maximum amount of time (in seconds) that curl_easy_perform will wait for the request to complete before timing out and returning an error. */
  curl_easy_setopt(handle, CURLOPT_TIMEOUT, 5L);

  /* specifies whether curl should follow HTTP redirects automatically. A value of 1L indicates that redirects should be followed. */
  curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);

  /* sets the maximum number of HTTP redirects that curl should follow automatically. */
  curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 10L);

  /* sets the maximum amount of time (in seconds) that curl should wait for a connection to be established before timing out and returning an error. */
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 2L);

  /* specifies the name of a file to read cookies from for the request. An empty string indicates that no cookie file should be used. */
  curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");

  /*specifies whether curl should retrieve the modification time of the requested resource and store it in the info structure. */
  curl_easy_setopt(handle, CURLOPT_FILETIME, 1L);

  /* sets the value of the User-Agent HTTP header to a string indicating the name of the client making the request. */
  curl_easy_setopt(handle, CURLOPT_USERAGENT, "mini crawler");

  /* specifies the type of HTTP authentication to use. */
  curl_easy_setopt(handle, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

  /* specifies whether curl should continue sending authentication credentials to the server after receiving a 401 response. */
  curl_easy_setopt(handle, CURLOPT_UNRESTRICTED_AUTH, 1L);

  /* specifies the type of authentication to use for the proxy server. */
  curl_easy_setopt(handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);

  /* sets the timeout (in milliseconds) for the Expect: 100-continue handshake. */
  curl_easy_setopt(handle, CURLOPT_EXPECT_100_TIMEOUT_MS, 0L);


  // Finally return the handle

  return handle;
}

/* HREF finder implemented in libxml2 but could be any HTML parser */

// Takes new links grabbed from the site and follows them
// to ensure link validity
size_t follow_links(CURLM *multi_handle, memory *mem, char *url)
{
  int opts = HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | \
             HTML_PARSE_NOWARNING | HTML_PARSE_NONET;
  htmlDocPtr doc = htmlReadMemory(mem->buf, mem->size, url, NULL, opts);
  if(!doc)
    return 0;
    // Sets pretext to follow all "href" links in doc
  xmlChar *xpath = (xmlChar*) "//a/@href";
  // Sets context to HTML document
  xmlXPathContextPtr context = xmlXPathNewContext(doc);
  // Assigns all hrefs found in context to the variable result
  xmlXPathObjectPtr result = xmlXPathEvalExpression(xpath, context);
  xmlXPathFreeContext(context);
  // Return 0 if no results found
  if(!result)
    return 0;
  xmlNodeSetPtr nodeset = result->nodesetval;
  if(xmlXPathNodeSetIsEmpty(nodeset)) {
    xmlXPathFreeObject(result);
    return 0;
  }
  size_t count = 0;
  int i;

  // Randomizes list of which links to follow
  // NOT first come first serve
  // In an effort to avoid efficiency losses
  for(i = 0; i < nodeset->nodeNr; i++) {
    double r = rand();
    int x = r * nodeset->nodeNr / RAND_MAX;
    const xmlNode *node = nodeset->nodeTab[x]->xmlChildrenNode;
    xmlChar *href = xmlNodeListGetString(doc, node, 1);
    if(follow_relative_links) {
      xmlChar *orig = href;
      href = xmlBuildURI(href, (xmlChar *) url);
      xmlFree(orig);
    }
    char *link = (char *) href;

    // Ensure that each href link receives begins with
    // properly either "http://" or "https://".
    if(!link || strlen(link) < 20)
      continue;
    if(!strncmp(link, "http://", 7) || !strncmp(link, "https://", 8)) {
      curl_multi_add_handle(multi_handle, make_handle(link));

      // Stops after we receive the Threshold of URLs per page.
      if(count++ == max_link_per_page)
        break;
    }
    xmlFree(link);
  }
  xmlXPathFreeObject(result);
  return count;
}

// Returns True or False depending on validity of text
int is_html(char *ctype)
{
  return ctype != NULL && strlen(ctype) > 10 && strstr(ctype, "text/html");
}


void *init_curl(void *start_page) {
      /*sets up a multi-handle to perform multiple HTTP requests in parallel using libcurl.
    It sets the maximum number of total connections to max_con and the maximum number of connections per host to 6.
    The signal function sets up a signal handler for SIGINT, which is used to interrupt the program with Ctrl+C.
    The LIBXML_TEST_VERSION macro initializes the libxml library.
    The curl_global_init function initializes the libcurl library. */
  signal(SIGINT, sighandler);
  LIBXML_TEST_VERSION;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURLM *multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, max_con);
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, 6L);

  /* enables http/2 if available */
#ifdef CURLPIPE_MULTIPLEX
  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
#endif

  //void *start_page = (void *) start_page;
  /* sets html start page */
  curl_multi_add_handle(multi_handle, make_handle(start_page));

  int msgs_left;
  int pending = 0;
  int complete = 0;
  int still_running = 1;
  while(still_running && !pending_interrupt) {
    int numfds;
    curl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);
    curl_multi_perform(multi_handle, &still_running);

    /* See how the transfers went */
    CURLMsg *m = NULL;
    while((m = curl_multi_info_read(multi_handle, &msgs_left))) {
      if(m->msg == CURLMSG_DONE) {
        CURL *handle = m->easy_handle;
        char *url;
        memory *mem;
        curl_easy_getinfo(handle, CURLINFO_PRIVATE, &mem);
        curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &url);

        if(m->data.result == CURLE_OK) {
          long res_status;
          curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &res_status);
          if(res_status == 200) {
            char *ctype;
            curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &ctype);



            FILE* fptr = fopen("visited.txt", "a");
            fprintf(fptr, "[%d] HTTP %d: %s\n", complete, (int) res_status, url);
            fclose(fptr);



            //printf("[%d] HTTP 200 (%s): %s\n", complete, ctype, url);
            if(is_html(ctype) && mem->size > 100) {
              if(pending < max_requests && (complete + pending) < max_total) {
                pending += follow_links(multi_handle, mem, url);
                still_running = 1;
              }
            }
          }
          else {
            printf(RED"[%d] HTTP %d: %s\n"NORMAL, complete, (int) res_status, url);
          }
        }
        else {
          printf(RED"[%d] Connection failure: %s\n"NORMAL, complete, url);
        }
        curl_multi_remove_handle(multi_handle, handle);
        curl_easy_cleanup(handle);
        free(mem->buf);
        free(mem);
        complete++;
        pending--;
      }

    }
  }
  curl_multi_cleanup(multi_handle);
  curl_global_cleanup();
  printf("\n\n");
 }

int main(void)
{



  int numURLs = 10;
  char urls[numURLs][100];


  // Ask user which file contains the URLs
  printf("\n\nPlease enter the file name. Be sure to include the extension (ex: .txt): ");

  // Store the user's file name in a char array
  char inputFileName[100];

  // Prompt the user to enter the file name
  scanf("%s", inputFileName);


    FILE* fp = fopen(inputFileName, "r");
    if (fp == NULL) {
        printf("Error: could not open file\n");
        return 1;
    }
    int i = 0;
    char buffer[MAX_URL_LENGTH];
    while (fgets(buffer, MAX_URL_LENGTH, fp) != NULL && i < MAX_URLS) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0'; // remove trailing newline
            len--; // reduce length by 1
        }
        if (len > 0 && buffer[len - 1] == '\r') {
            buffer[len - 1] = '\0'; // remove trailing EOF character on Windows
        }
        strcpy(urls[i], buffer);
        i++;
    }
    fclose(fp);

    pthread_t tid[i];

    for (int j = 0; j < i; j++) {
        char *page = urls[j];
        printf(GREEN"STARTING CRAWL ON: %s\n\n"NORMAL, page);

        printf("HTTP and Connection Errors: \n");
        init_curl(page);
    }

    printf("Crawl complete!\n");
  return 0;
}

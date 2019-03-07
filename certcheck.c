/* COMP30023 Project 2 certcheck
 * By Hongfei Yang <hongfeiy1@student.unimelb.edu.au>
 * 24/05/2018
 */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>

#define EXTNAME_LEN 2048
#define VALID 1                 // flag for valid cert in verify
#define INVALID 0               // flag for invalid cert in verify
#define INIT_SIZE 4             // initial size of any malloc arrays
#define NAME_LEN 1000           // max length of a website or cert_name
#define VALID_PKEY_LENGTH 256   // minimum length required for RSA keys

// struct to store single line in csv
typedef struct {
    char cert_name[NAME_LEN];
    char website[NAME_LEN];
} entry_t;

// struct to store a single csv files
typedef struct {
    entry_t* data;
    int len;
    int size;
} csv_file_t;


// read a single csv file into a struct
csv_file_t* read_csv(char* csv_filename) {

    FILE* file_ptr = fopen(csv_filename, "r");

    assert(file_ptr);

    entry_t* all_entries;
    int size = INIT_SIZE;

    all_entries = (entry_t*)malloc(size * sizeof(*all_entries));
    assert(all_entries);    


    int len = 0;

    int c;

    // read each line
    while ((c = fscanf(file_ptr, "%[^,],%[^\n]\n", all_entries[len].cert_name, all_entries[len].website)) > 0) {

        len++;

        // increase size of array if exceeded
        if (len == size) {
            size = size* 2;
            all_entries = (entry_t*)realloc(all_entries, sizeof(*all_entries)*size);
            assert(all_entries);
        }
    }


    // put the array of entries into a csv_file_t
    csv_file_t* csv_file = (csv_file_t*)malloc(sizeof(*csv_file));
    assert(csv_file);

    csv_file->data = all_entries;
    csv_file->len = len;
    csv_file->size = size;

    fclose(file_ptr);

    return csv_file;
}



// split a string by a delim, each substring has head removed by an offset len,
// the length of string is then stored in num
char** strsplit(char* string, const char* delim, int offset, int* num) {

    // duplicate string first because strtok() needs to operate on writable
    // string
    char* str = strdup(string);

    // split a string by delimiter
    char* tok = strtok(str, delim);

    // allocate memory for the array of substrings
    int size = INIT_SIZE;

    char** tokens = malloc(sizeof(*tokens) * size);
    assert(tokens);

    // iterate through each split and store in an array
    while (tok!=NULL) {

        tokens[*num] = malloc((strlen(tok) + 1) * sizeof(char));

        strcpy(tokens[*num], tok + offset);

        *num += 1;

        // increase size of the array if needed
        if (*num == size) {

            size *= 2;

            tokens = realloc(tokens, size * sizeof(*tokens));

            assert(tokens);

        }

        // strtok() then searches from the last position to get another split
        tok = strtok(NULL, delim);
        
    }

    return tokens;
}

// helper function to free the 2d array allocated to store an array of substring
void free_tokens(char** tokens, int num) {

    for (int i=0; i<num; i++) {
        free(tokens[i]);
    }
    free(tokens);
}

// check domains of a given website against a name in cert
bool check_domain(char* website, char* subject_CN) {

    // split each args into array of substrings first
    int n_CN_tokens = 0;

    char** CN_tokens = strsplit(subject_CN, ".", 0, &n_CN_tokens);

    int n_website_tokens = 0;

    char** website_tokens = strsplit(website, ".", 0, &n_website_tokens);

    bool result = true;

    int i;

    // now compare each dot separated section

    if (n_CN_tokens != n_website_tokens) {
        // if they have different number of sections, they cannot match
        result = false;
    } else {
        // they have same number of sections, check each section
        for (i=0; i<n_CN_tokens; i++) {
            
            if (strcmp(CN_tokens[i], "*") == 0) {
                // if one of the section is *, skip.
                // (assume this the first section :))
            } else {
                // if it is not a '*', then they have to match to pass the test
                if (strcmp(CN_tokens[i], website_tokens[i]) != 0) {
                    result = false;
                    break;

                }
            }
        }
    }

    // free
    free_tokens(website_tokens, n_website_tokens);
    free_tokens(CN_tokens, n_CN_tokens);

    return result;

}

// check a given ASN1_TIME against current time
int check_date_time(ASN1_TIME* time) {
    int day, sec;

    // check time difference against current time
    if (!ASN1_TIME_diff(&day, &sec, NULL, time)) {
        perror("invalid time format\n");
    }

    // check day and sec
    if (day > 0 || sec > 0) {
        return 1;   // later
    } else if (day < 0 || sec < 0) {
        return -1;  // sooner
    } else {
        return 0;   // same
    }
}

// verify a website against a cert
int verify(char* test_cert_example, char* website) {
    
    bool outcome = true;

    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, test_cert_example)))
    {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    //cert contains the x509 certificate and can be used to analyse the certificate

    // GET SUBJECT NAME
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0); 

    // GET SUBJECT COMMON NAME LOCATION IN THE STRING
    char* subject_CN = strstr(subj, "CN=") + strlen("CN=");

    // check against common name first and keep track of this record
    bool is_CN_match_domain = check_domain(website, subject_CN);


    // get 'not before', 'not after' fields in cert
    ASN1_TIME* notBefore = X509_get_notBefore(cert);
    ASN1_TIME* notAfter = X509_get_notAfter(cert);

    // check date time against current date time
    if (!(check_date_time(notBefore) == -1 && check_date_time(notAfter) == 1)) {
        printf("Time check failed\n");
        return INVALID;
    }
    

    // retrieve public key from cert
    EVP_PKEY* pkey = X509_get_pubkey(cert);

    // get RSA key from it
    RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);

    // then get the key length, in bytes
    int key_length = RSA_size(rsa_key);

    // free
    RSA_free(rsa_key);
    EVP_PKEY_free(pkey);

    // check key length
    if (key_length < VALID_PKEY_LENGTH) {
        printf("Key length is too small (%d bytes)\n", key_length);
        return INVALID;
    }

    // check extensions

    // get a stack of extensions first
    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

    // get the number of extensions
    int num_of_exts;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    } else {
        num_of_exts = 0;
    }
 

    // iterate through all extensions, only check the required ones
    for (int i=0; i < num_of_exts; i++) {

        // get extension
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);

        // get object from extension
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

        // get extension BIO from memory
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
            M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
        }

        // then read from memory to get the extension value
        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // make the extension value a null-byte terminated string
        bptr->data[bptr->length] = '\0';

        BIO_free(ext_bio);

        // get NID from object
        unsigned nid = OBJ_obj2nid(obj);

        if (nid == NID_undef) {
            // no lookup found for the provided OID so
            // nid came back as undefined.
            char extname[EXTNAME_LEN];
            OBJ_obj2txt(extname, EXTNAME_LEN, (const ASN1_OBJECT *) obj, 1);
            printf("extension name is %s, but it does not have a known NID\n",
                    extname);
        } else {
            // the OID translated to a NID which implies
            // that the OID has a known sn/ln
            
            //const char *c_ext_name = OBJ_nid2ln(nid);
            //printf("extension name is %s\n", c_ext_name);
            
            // get data
            char* extension_value = bptr->data;


            switch (nid) {
                // verify basic constraints
                case NID_basic_constraints:
                if (strstr(extension_value, "CA:TRUE")) {
                    outcome = false;
                    printf("Basic Constaints validation failed\n");
                }
                break;

                // verify extended key usage
                case NID_ext_key_usage:
                if (!strstr(extension_value, "TLS Web Server Authentication")) {
                    outcome = false;
                    printf("Extended Key Usage validation failed\n");
                }
                break;

                // verify subject alternative name
                case NID_subject_alt_name:

                // check SAN if the website name is not matched to default
                // common names
                if (!is_CN_match_domain) {
                 
                    int num = 0;

                    // split SAN value into a list of domain names
                    char** SANs = strsplit(extension_value, ", ",
                                            strlen("DNS:"), &num);

                    // then check each to see it there is thing 
                    for (int i=0; i<num; i++) {

                        if (check_domain(website, SANs[i])) {
                            // found a match
                            is_CN_match_domain = true;
                            break;
                        }
                    }

                    free_tokens(SANs, num);
                }
                break;
            }
        }

        // do not need to check others if one field already failed the test
        if (!outcome) {
            break;
        }

    }

    X509_free(cert);
    BIO_free_all(certificate_bio);


    // false means it failed both Common Name and SAN, so it is definitely
    // invalid
    if (is_CN_match_domain == false) {
        printf("Domain validation failed\n");
        return INVALID;
    }

    // failed other test
    if (!outcome) {
        return INVALID;
    }

    return VALID;
}

// create a output csv file using the given input file and the result
// from the verification
void create_output_csv(csv_file_t* input_file, int* result) {

    FILE* fp = fopen("output.csv", "w");

    int i;
    for (i = 0; i < input_file->len; i++) {
        fprintf(fp, "%s,%s,%d\n", input_file->data[i].cert_name,
                                  input_file->data[i].website, result[i]);
    }

    fclose(fp);
}


int main(int argc, char** argv) {

    // read the csv file first
    csv_file_t* csv_file = read_csv(argv[1]);

    int len = csv_file->len;
    entry_t* all_entries = csv_file->data;

    int i;

    // allocated memory to store result
    int* result = malloc(csv_file->len * sizeof(int));
    assert(result);

    for (i=0; i<len; i++) {

        //printf("checking %s    %s\n", all_entries[i].cert_name,
        //                              all_entries[i].website);

        // verify this entry
        result[i] = verify(all_entries[i].cert_name, all_entries[i].website);
        //printf("\n");

    }

    // create 'output.csv'
    create_output_csv(csv_file, result);

    // free everything
    free(csv_file->data);
    free(csv_file);
    free(result);

}

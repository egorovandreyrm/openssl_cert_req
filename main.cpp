#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#define CERT_REQUEST_KEY_PATH  "root.key"
#define GENERATED_CERT_REQUEST_SAVE_PATH  "generated_request.csr"

#define CERT_CA_PATH "ca.pem"
#define CERT_CA_KEY_PATH "root.key"
#define GENERATED_CERT_SAVE_PATH "generated_cert.crt"

// the app mimics the following two commands.
//
// openssl req -new -key CERT_REQUEST_KEY_PATH -out GENERATED_CERT_REQUEST_SAVE_PATH
// openssl x509 -req -in GENERATED_CERT_SAVE_PATH -CA CERT_CA_PATH -CAkey CERT_CA_KEY_PATH -CAcreateserial -out GENERATED_CERT_SAVE_PATH -days 5000

X509_REQ *generate_cert_req(const char *p_path) {
    FILE *p_file = NULL;
    EVP_PKEY *p_key = NULL;
    X509_REQ *p_x509_req = NULL;

    p_file = fopen(p_path, "r");
    if (NULL == p_file) {
        printf("failed to open the private key file\n");
        return NULL;
    }

    p_key = PEM_read_PrivateKey(p_file, NULL, NULL, NULL);
    fclose(p_file);

    if (NULL == p_key) {
        printf("failed to read the private key file\n");
        return NULL;
    }

    p_x509_req = X509_REQ_new();
    if (NULL == p_x509_req) {
        printf("failed to create a new X509 REQ\n");
        EVP_PKEY_free(p_key);
        return NULL;
    }

    if (0 > X509_REQ_set_pubkey(p_x509_req, p_key)) {
        printf("failed to set pub key\n");
        X509_REQ_free(p_x509_req);
        EVP_PKEY_free(p_key);
        return NULL;
    }

    if (0 > X509_REQ_sign(p_x509_req, p_key, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_REQ_free(p_x509_req);
        EVP_PKEY_free(p_key);
        return NULL;
    }

    EVP_PKEY_free(p_key);
    return p_x509_req;
}

int randSerial(ASN1_INTEGER *ai) {
    int ret = -1;

    BIGNUM *btmp = BN_new();
    if (btmp == NULL)
        return 0;

    if (!BN_pseudo_rand(btmp, 64, 0, 0)) {
        goto error;
    }

    if (ai && !BN_to_ASN1_INTEGER(btmp, ai)) {
        goto error;
    }

    ret = 1;

    error:
    BN_free(btmp);

    return ret;
}

X509 *generate_cert(X509_REQ *pCertReq, const char *p_ca_path, const char *p_ca_key_path) {
    FILE *p_ca_file = fopen(p_ca_path, "r");
    if (NULL == p_ca_file) {
        printf("failed to open the ca file\n");
        return NULL;
    }

    X509 *p_ca_cert = PEM_read_X509(p_ca_file, NULL, 0, NULL);
    fclose(p_ca_file);

    if (NULL == p_ca_cert) {
        printf("failed to read X509 CA certificate\n");
        return NULL;
    }

    EVP_PKEY *p_ca_pkey = X509_get_pubkey(p_ca_cert);
    X509_free(p_ca_cert);

    if (NULL == p_ca_pkey) {
        printf("failed to get X509 CA pkey\n");
        return NULL;
    }

    FILE *p_ca_key_file = fopen(p_ca_key_path, "r");
    if (NULL == p_ca_key_file) {
        printf("failed to open the private key file\n");
        return NULL;
    }

    EVP_PKEY *p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, NULL, NULL, NULL);
    fclose(p_ca_key_file);

    if (NULL == p_ca_key_pkey) {
        printf("failed to read the private key file\n");
        return NULL;
    }

    X509 *p_generated_cert = X509_new();
    if (NULL == p_generated_cert) {
        printf("failed to create a new X509\n");
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        return NULL;
    }

    ASN1_INTEGER *p_serial_number = ASN1_INTEGER_new();
    randSerial(p_serial_number);
    X509_set_serialNumber(p_generated_cert, p_serial_number);
    ASN1_INTEGER_free(p_serial_number);

    X509_set_issuer_name(p_generated_cert, X509_REQ_get_subject_name(pCertReq));
    X509_set_subject_name(p_generated_cert, X509_REQ_get_subject_name(pCertReq));

    X509_gmtime_adj(X509_get_notBefore(p_generated_cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 31536000L);

    EVP_PKEY *p_cert_req_pkey = X509_REQ_get_pubkey(pCertReq);
    if (NULL == p_cert_req_pkey) {
        printf("failed to get certificate req pkey\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    if (0 > X509_set_pubkey(p_generated_cert, p_cert_req_pkey)) {
        printf("failed to set pkey\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    if (0 > EVP_PKEY_copy_parameters(p_ca_pkey, p_ca_key_pkey)) {
        printf("failed to copy parameters\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));

    if (0 > X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        goto CLEANUP;
    }

    CLEANUP:
    EVP_PKEY_free(p_cert_req_pkey);
    EVP_PKEY_free(p_ca_key_pkey);
    EVP_PKEY_free(p_ca_pkey);

    return p_generated_cert;
}

int save_cert_req(X509_REQ *p_cert_req, const char *path) {
    FILE *p_file = fopen(path, "w");
    if (NULL == p_file) {
        printf("failed to open file for saving csr\n");
        fclose(p_file);
        return -1;
    }

    PEM_write_X509_REQ(p_file, p_cert_req);
    fclose(p_file);
    return 0;
}

int save_cert(X509 *p_generated_cert, const char *path) {
    FILE *p_file = fopen(path, "w");
    if (NULL == p_file) {
        printf("failed to open file for saving csr\n");
        fclose(p_file);
        return -1;
    }

    PEM_write_X509(p_file, p_generated_cert);
    fclose(p_file);
    return 0;
}

int main() {
    int ret = 0;
    X509_REQ *p_cert_req = NULL;
    X509 *p_generated_cert = NULL;

    p_cert_req = generate_cert_req(CERT_REQUEST_KEY_PATH);
    if (NULL == p_cert_req) {
        printf("failed to generate cert req\n");
        ret = -1;
        goto CLEANUP;
    }

    if (save_cert_req(p_cert_req, GENERATED_CERT_REQUEST_SAVE_PATH)) {
        printf("failed to save generated cert request\n");
        ret = -1;
        goto CLEANUP;
    }

    p_generated_cert = generate_cert(p_cert_req, CERT_CA_PATH, CERT_CA_KEY_PATH);
    if (NULL == p_generated_cert) {
        printf("failed to generate cert\n");
        ret = -1;
        goto CLEANUP;
    }

    if (save_cert(p_generated_cert, GENERATED_CERT_SAVE_PATH)) {
        printf("failed to save generated cert\n");
        ret = -1;
        goto CLEANUP;
    }

    printf("the certificates have been generated.");

    CLEANUP:
    X509_REQ_free(p_cert_req);
    X509_free(p_generated_cert);

    return ret;
}
// ============================================================================
// send_email.cpp — Simple SMTP Email Sender using libcurl
// ----------------------------------------------------------------------------
// Used by BCord backend for verification emails
// ============================================================================

#include <curl/curl.h>
#include <cstring>   // ✅ Needed for memcpy()
#include <string>
#include <iostream>

bool send_email(const std::string &to, const std::string &subject, const std::string &body) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[Email] Failed to init CURL" << std::endl;
        return false;
    }

    const std::string from = "no-reply@bcord.run.place";
    std::string payload =
        "To: " + to + "\r\n"
        "From: " + from + "\r\n"
        "Subject: " + subject + "\r\n"
        "\r\n" + body + "\r\n";

    struct curl_slist *recipients = nullptr;
    recipients = curl_slist_append(recipients, to.c_str());

    // TODO: Replace these values with your actual SMTP credentials
    curl_easy_setopt(curl, CURLOPT_USERNAME, "smtp_user");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "smtp_password");
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.yourprovider.com:587");

    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from.c_str());
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    // Read payload callback
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, +[](char *ptr, size_t size, size_t nmemb, void *userp) -> size_t {
        std::string *data = static_cast<std::string *>(userp);
        if (data->empty()) return 0;
        size_t copy_len = std::min(size * nmemb, data->size());
        memcpy(ptr, data->c_str(), copy_len);
        data->erase(0, copy_len);
        return copy_len;
    });
    curl_easy_setopt(curl, CURLOPT_READDATA, &payload);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    CURLcode res = curl_easy_perform(curl);
    bool success = (res == CURLE_OK);

    if (!success)
        std::cerr << "[Email] CURL error: " << curl_easy_strerror(res) << std::endl;

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    return success;
}


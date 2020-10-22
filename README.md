# chrome-78-cookie-store-analysis
源码过程分析:
第一，chrome创建一个url请求的时候，如何获取cookie，源码文件名network_context.cc，
      在MakeURLRequestContext方法中调用:
      crypto_delegate = cookie_config::GetCookieCryptoDelegate();
      cookie_config namespace下的GetCookieCryptoDelegate方法,接着看道头文件中 #include "components/cookie_config/cookie_store_util.h"
      猜测GetCookieCryptoDelegate在cookie_store_util.h中定义,查看其源代码，如下
      namespace net {
          class CookieCryptoDelegate;
      }  // namespace net

      namespace cookie_config {

      // Factory method for returning a CookieCryptoDelegate if one is appropriate for
      // this platform. The object returned is a LazyInstance. Ownership is not
      // transferred.
      net::CookieCryptoDelegate* GetCookieCryptoDelegate();

    }  // namespace cookie_config
    可以看到，是有这个方法，接着再其对应cookie_store_util.cc文件中，查看其实现方式：
    namespace cookie_config {
        #if defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX)
        namespace {

        // Use the operating system's mechanisms to encrypt cookies before writing
        // them to persistent store.  Currently this only is done with desktop OS's
        // because ChromeOS and Android already protect the entire profile contents.
        class CookieOSCryptoDelegate : public net::CookieCryptoDelegate {
         public:
          bool ShouldEncrypt() override;
          bool EncryptString(const std::string& plaintext,
                             std::string* ciphertext) override;
          bool DecryptString(const std::string& ciphertext,
                             std::string* plaintext) override;
        };

        bool CookieOSCryptoDelegate::ShouldEncrypt() {
        #if defined(OS_IOS)
          // Cookie encryption is not necessary on iOS, due to OS-protected storage.
          // However, due to https://codereview.chromium.org/135183021/, cookies were
          // accidentally encrypted. In order to allow these cookies to still be used,a
          // a CookieCryptoDelegate is provided that can decrypt existing cookies.
          // However, new cookies will not be encrypted. The alternatives considered
          // were not supplying a delegate at all (thus invalidating all existing
          // encrypted cookies) or in migrating all cookies at once, which may impose
          // startup costs.  Eventually, all cookies will get migrated as they are
          // rewritten.
          return false;
        #else
          return true;
        #endif
        }

        bool CookieOSCryptoDelegate::EncryptString(const std::string& plaintext,
                                                   std::string* ciphertext) {
          return OSCrypt::EncryptString(plaintext, ciphertext);
        }

        bool CookieOSCryptoDelegate::DecryptString(const std::string& ciphertext,
                                                   std::string* plaintext) {
          return OSCrypt::DecryptString(ciphertext, plaintext);
        }

        // Using a LazyInstance is safe here because this class is stateless and
        // requires 0 initialization.
        base::LazyInstance<CookieOSCryptoDelegate>::DestructorAtExit
            g_cookie_crypto_delegate = LAZY_INSTANCE_INITIALIZER;

        }  // namespace

        net::CookieCryptoDelegate* GetCookieCryptoDelegate() {
          return g_cookie_crypto_delegate.Pointer();
        }
        #else   // defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX)
        net::CookieCryptoDelegate* GetCookieCryptoDelegate() {
          return NULL;
        }
        #endif  // defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX)

        }  // namespace cookie_config

      可以看到里边定义了，cookie的加密和解密方法以及各种不同平台是否需要加密,其中ios平台不需要加密,加密解密时调用了OSCrypt::DecryptString和OSCrypt::EncryptString方法，再查看头文件#include "components/os_crypt/os_crypt.h",找os_crypt，发现在不同的系统平台下，有不同的实现方式，本文重点分析windows平台下的实现os_crypt_win.cc,源码如下：



        #include "components/os_crypt/os_crypt.h"

        #include <windows.h>

        #include "base/strings/utf_string_conversions.h"
        #include "base/win/wincrypt_shim.h"

        bool OSCrypt::EncryptString16(const base::string16& plaintext,
                                      std::string* ciphertext) {
          return EncryptString(base::UTF16ToUTF8(plaintext), ciphertext);
        }

        bool OSCrypt::DecryptString16(const std::string& ciphertext,
                                      base::string16* plaintext) {
          std::string utf8;
          if (!DecryptString(ciphertext, &utf8))
            return false;

          *plaintext = base::UTF8ToUTF16(utf8);
          return true;
        }

        bool OSCrypt::EncryptString(const std::string& plaintext,
                                    std::string* ciphertext) {
          DATA_BLOB input;
          input.pbData = const_cast<BYTE*>(
              reinterpret_cast<const BYTE*>(plaintext.data()));
          input.cbData = static_cast<DWORD>(plaintext.length());

          DATA_BLOB output;
          BOOL result =
              CryptProtectData(&input, L"", nullptr, nullptr, nullptr, 0, &output);
          if (!result) {
            PLOG(ERROR) << "Failed to encrypt";
            return false;
          }

          // this does a copy
          ciphertext->assign(reinterpret_cast<std::string::value_type*>(output.pbData),
                             output.cbData);

          LocalFree(output.pbData);
          return true;
        }

        bool OSCrypt::DecryptString(const std::string& ciphertext,
                                    std::string* plaintext) {
          DATA_BLOB input;
          input.pbData = const_cast<BYTE*>(
              reinterpret_cast<const BYTE*>(ciphertext.data()));
          input.cbData = static_cast<DWORD>(ciphertext.length());

          DATA_BLOB output;
          BOOL result = CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                                           0, &output);
          if (!result) {
            PLOG(ERROR) << "Failed to decrypt";
            return false;
          }

          plaintext->assign(reinterpret_cast<char*>(output.pbData), output.cbData);
          LocalFree(output.pbData);
          return true;
        }
        
        里边定义了cookie最终使用的加密和解密的方法，才用了windows加密解密API CryptProtectData 和 CryptUnprotectData这2个方法，至此分析完成。

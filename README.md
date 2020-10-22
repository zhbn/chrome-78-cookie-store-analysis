# chromium-78-cookie-store-analysis  chrome chomium cookie 读取保存加密解密过程分析
源码过程分析:
       第一，chrome创建一个url请求的时候，如何获取cookie，源码文件名network_context.cc，
      在MakeURLRequestContext方法中调用:
      crypto_delegate = cookie_config::GetCookieCryptoDelegate();
      cookie_config namespace下的GetCookieCryptoDelegate方法,
      接着看道头文件中 #include "components/cookie_config/cookie_store_util.h"
      猜测GetCookieCryptoDelegate在cookie_store_util.h中定义,
      查看其源代码，如下
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

      可以看到里边定义了，cookie的加密和解密方法以及各种不同平台是否需要加密,
      其中ios平台不需要加密,加密解密时调用了OSCrypt::DecryptString和OSCrypt::EncryptString方法，
      再查看头文件#include "components/os_crypt/os_crypt.h",
      找os_crypt，发现在不同的系统平台下，有不同的实现方式，
      本文重点分析windows平台下的实现os_crypt_win.cc,源码如下：



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
        
        里边定义了cookie最终使用的加密和解密的方法，才用了windows加密解密API CryptProtectData 
        和 CryptUnprotectData这2个方法，
        至此chromium cookie加密解密方法分析完成。

第二：cookie保存过程分析
      再第一步的分析中,network_context.cc文件中，
      在MakeURLRequestContext方法中调用:
      crypto_delegate = cookie_config::GetCookieCryptoDelegate()
      ;创建了一个加密解密的对象，后面是如何传递到cookie读取保存时用于加密解密呢，再这个文件中继续向下分析，可以看到
          scoped_refptr<net::SQLitePersistentCookieStore> sqlite_store(
              new net::SQLitePersistentCookieStore(
                  params_->cookie_path.value(), client_task_runner,
                  background_task_runner, params_->restore_old_session_cookies,
                  crypto_delegate));
       将crypto_delegate传到了net::SQLitePersistentCookieStore
       这个对象中，这个对象的源文件是sqlite_persistent_cookie_store.cc文件，可以看到保存过程如下：
       case PendingOperation::COOKIE_ADD:
          add_smt.Reset(true);
          add_smt.BindInt64(0, po->cc().CreationDate().ToInternalValue());
          add_smt.BindString(1, po->cc().Domain());
          add_smt.BindString(2, po->cc().Name());
          if (crypto_ && crypto_->ShouldEncrypt()) {
            std::string encrypted_value;
            if (!crypto_->EncryptString(po->cc().Value(), &encrypted_value)) {
              DLOG(WARNING) << "Could not encrypt a cookie, skipping add.";
              RecordCookieCommitProblem(COOKIE_COMMIT_PROBLEM_ENCRYPT_FAILED);
              trouble = true;
              continue;
            }
            add_smt.BindCString(3, "");  // value
            // BindBlob() immediately makes an internal copy of the data.
            add_smt.BindBlob(4, encrypted_value.data(),
                             static_cast<int>(encrypted_value.length()));
          } else {
            add_smt.BindString(3, po->cc().Value());
            add_smt.BindBlob(4, "", 0);  // encrypted_value
          }
          add_smt.BindString(5, po->cc().Path());
          add_smt.BindInt64(6, po->cc().ExpiryDate().ToInternalValue());
          add_smt.BindInt(7, po->cc().IsSecure());
          add_smt.BindInt(8, po->cc().IsHttpOnly());
          add_smt.BindInt(
              9, CookieSameSiteToDBCookieSameSite(po->cc().SameSite()));
          add_smt.BindInt64(10, po->cc().LastAccessDate().ToInternalValue());
          add_smt.BindInt(11, po->cc().IsPersistent());
          add_smt.BindInt(12, po->cc().IsPersistent());
          add_smt.BindInt(
              13, CookiePriorityToDBCookiePriority(po->cc().Priority()));
          if (!add_smt.Run()) {
            DLOG(WARNING) << "Could not add a cookie to the DB.";
            RecordCookieCommitProblem(COOKIE_COMMIT_PROBLEM_ADD);
            trouble = true;
          }
          break;
            可以看到 crypto_->EncryptString(po->cc().Value(), &encrypted_value)
             将cookie值加密，后面赋值给 add_smt.BindBlob(4, encrypted_value.data(),          
     
             sql插入的第4个字段，再往上看，可以看到sql过程创建的方法如下：
              sql::Statement add_smt(db()->GetCachedStatement(
            SQL_FROM_HERE,
            // TODO(chlily): These are out of order with respect to the schema
            // declaration. Fix this.
            "INSERT INTO cookies (creation_utc, host_key, name, value, "
            "encrypted_value, path, expires_utc, is_secure, is_httponly, "
            "samesite, last_access_utc, has_expires, is_persistent, priority) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
             可以看到第4个字段为表单的encrypted_value字段，至此分析完成。

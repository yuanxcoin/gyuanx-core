// Copyright (c) 2018-2020, The Gyuanx Project
// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
//
#include "file.h"
#include "epee/misc_log_ex.h"
#include <unistd.h>
#include <cstdio>

#ifdef WIN32
#include "epee/string_tools.h"
#ifndef STRSAFE_NO_DEPRECATE
#define STRSAFE_NO_DEPRECATE
#endif
  #include <windows.h>
  #include <shlobj.h>
  #include <strsafe.h>
#else 
  #include <sys/file.h>
  #include <sys/utsname.h>
  #include <sys/stat.h>
#endif

#ifdef __GLIBC__
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <cstring>
#include <cctype>
#endif

#include "cryptonote_config.h"

#undef GYUANX_DEFAULT_LOG_CATEGORY
#define GYUANX_DEFAULT_LOG_CATEGORY "util"

namespace tools {

#ifndef _WIN32
  static int flock_exnb(int fd)
  {
    struct flock fl;
    int ret;

    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    ret = fcntl(fd, F_SETLK, &fl);
    if (ret < 0)
      MERROR("Error locking fd " << fd << ": " << errno << " (" << strerror(errno) << ")");
    return ret;
  }
#endif

  private_file::private_file() noexcept : m_handle(), m_filename() {}

  private_file::private_file(std::FILE* handle, fs::path filename) noexcept
    : m_handle(handle), m_filename(std::move(filename)) {}

  private_file private_file::create(fs::path name)
  {
#ifdef WIN32
    struct close_handle
    {
      void operator()(HANDLE handle) const noexcept
      {
        CloseHandle(handle);
      }
    };

    std::unique_ptr<void, close_handle> process = nullptr;
    {
      HANDLE temp{};
      const bool fail = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, std::addressof(temp)) == 0;
      process.reset(temp);
      if (fail)
        return {};
    }

    DWORD sid_size = 0;
    GetTokenInformation(process.get(), TokenOwner, nullptr, 0, std::addressof(sid_size));
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      return {};

    std::unique_ptr<char[]> sid{new char[sid_size]};
    if (!GetTokenInformation(process.get(), TokenOwner, sid.get(), sid_size, std::addressof(sid_size)))
      return {};

    const PSID psid = reinterpret_cast<const PTOKEN_OWNER>(sid.get())->Owner;
    const DWORD daclSize =
      sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD);

    const std::unique_ptr<char[]> dacl{new char[daclSize]};
    if (!InitializeAcl(reinterpret_cast<PACL>(dacl.get()), daclSize, ACL_REVISION))
      return {};

    if (!AddAccessAllowedAce(reinterpret_cast<PACL>(dacl.get()), ACL_REVISION, (READ_CONTROL | FILE_GENERIC_READ | DELETE), psid))
      return {};

    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(std::addressof(descriptor), SECURITY_DESCRIPTOR_REVISION))
      return {};

    if (!SetSecurityDescriptorDacl(std::addressof(descriptor), true, reinterpret_cast<PACL>(dacl.get()), false))
      return {};

    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), std::addressof(descriptor), false};
    std::unique_ptr<void, close_handle> file{
      CreateFileW(
        name.c_str(),
        GENERIC_WRITE, FILE_SHARE_READ,
        std::addressof(attributes),
        CREATE_NEW, (FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE),
        nullptr
      )
    };
    if (file)
    {
      const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(file.get()), 0);
      if (0 <= fd)
      {
        file.release();
        std::FILE* real_file = _fdopen(fd, "w");
        if (!real_file)
        {
          _close(fd);
        }
        return {real_file, std::move(name)};
      }
    }
#else
    const int fdr = open(name.c_str(), (O_RDONLY | O_CREAT), S_IRUSR);
    if (0 <= fdr)
    {
      struct stat rstats = {};
      if (fstat(fdr, std::addressof(rstats)) != 0)
      {
        close(fdr);
        return {};
      }
      fchmod(fdr, (S_IRUSR | S_IWUSR));
      const int fdw = open(name.c_str(), O_RDWR);
      fchmod(fdr, rstats.st_mode);
      close(fdr);

      if (0 <= fdw)
      {
        struct stat wstats = {};
        if (fstat(fdw, std::addressof(wstats)) == 0 &&
            rstats.st_dev == wstats.st_dev && rstats.st_ino == wstats.st_ino &&
            flock_exnb(fdw) == 0 && ftruncate(fdw, 0) == 0)
        {
          std::FILE* file = fdopen(fdw, "w");
          if (file) return {file, std::move(name)};
        }
        close(fdw);
      }
    }
#endif
    return {};
  }

  private_file::~private_file() noexcept
  {
    std::error_code ignored;
    fs::remove(filename(), ignored);
  }

  file_locker::file_locker(const fs::path& filename)
  {
#ifdef WIN32
    m_fd = INVALID_HANDLE_VALUE;
    m_fd = CreateFileW(filename.c_str(), GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_fd != INVALID_HANDLE_VALUE)
    {
      OVERLAPPED ov;
      memset(&ov, 0, sizeof(ov));
      if (!LockFileEx(m_fd, LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov))
      {
        MERROR("Failed to lock " << filename << ": " << std::error_code(GetLastError(), std::system_category()));
        CloseHandle(m_fd);
        m_fd = INVALID_HANDLE_VALUE;
      }
    }
    else
    {
      MERROR("Failed to open " << filename << ": " << std::error_code(GetLastError(), std::system_category()));
    }
#else
    m_fd = open(filename.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (m_fd != -1)
    {
      if (flock_exnb(m_fd) == -1)
      {
        MERROR("Failed to lock " << filename << ": " << std::strerror(errno));
        close(m_fd);
        m_fd = -1;
      }
    }
    else
    {
      MERROR("Failed to open " << filename << ": " << std::strerror(errno));
    }
#endif
  }
  file_locker::~file_locker()
  {
    if (locked())
    {
#ifdef WIN32
      CloseHandle(m_fd);
#else
      close(m_fd);
#endif
    }
  }
  bool file_locker::locked() const
  {
#ifdef WIN32
    return m_fd != INVALID_HANDLE_VALUE;
#else
    return m_fd != -1;
#endif
  }


#ifdef WIN32
  fs::path get_special_folder_path(int nfolder, bool iscreate)
  {
    WCHAR psz_path[MAX_PATH] = L"";

    if (SHGetSpecialFolderPathW(NULL, psz_path, nfolder, iscreate))
    {
      return fs::path{psz_path};
    }

    LOG_ERROR("SHGetSpecialFolderPathW() failed, could not obtain requested path.");
    return "";
  }

  // Windows < Vista: C:\Documents and Settings\Username\Application Data\CRYPTONOTE_NAME
  // Windows >= Vista: C:\Users\Username\AppData\Roaming\CRYPTONOTE_NAME
  fs::path get_default_data_dir()
  {
    return get_special_folder_path(CSIDL_COMMON_APPDATA, true) / fs::u8path(CRYPTONOTE_NAME);
  }
#else
  // Non-windows: ~/.CRYPTONOTE_NAME
  fs::path get_default_data_dir()
  {
    char* home = std::getenv("HOME");
    return (home && std::strlen(home) ? fs::u8path(home) : fs::current_path()) / fs::u8path("." CRYPTONOTE_NAME);
  }
#endif

  bool create_directories_if_necessary(const fs::path& path)
  {
    std::error_code ec;
    if (fs::is_directory(path, ec))
    {
      return true;
    }

    bool res = fs::create_directories(path, ec);
    if (res)
    {
      LOG_PRINT_L2("Created directory: " << path);
    }
    else
    {
      LOG_PRINT_L2("Can't create directory: " << path << ", err: "<< ec.message());
    }

    return res;
  }

  void set_strict_default_file_permissions(bool strict)
  {
#if defined(__MINGW32__) || defined(__MINGW__)
    // no clue about the odd one out
#else
    mode_t mode = strict ? 077 : 0;
    umask(mode);
#endif
  }

  bool slurp_file(const fs::path& filename, std::string& contents)
  {
    fs::ifstream in;
    in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    try {
      in.open(filename, std::ios::binary | std::ios::in | std::ios::ate);
      contents.clear();
      contents.resize(in.tellg());
      in.seekg(0);
      in.read(contents.data(), contents.size());
      auto bytes_read = in.gcount();
      if (static_cast<size_t>(bytes_read) < contents.size())
        contents.resize(bytes_read);
      return true;
    } catch (...) {
      return false;
    }
  }

  bool dump_file(const fs::path& filename, std::string_view contents)
  {
    fs::ofstream out;
    out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    try {
      out.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
      out.write(contents.data(), contents.size());
      return true;
    } catch (...) {
      return false;
    }
  }

}

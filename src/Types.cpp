/*
MIT License

Copyright (c) 2020 Mikhail Milovidov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "Types.h"

//Qt includes
#include <QString>
#include <QStandardPaths>

using namespace QSsh;

const std::error_code QSsh::ssh2_success = std::error_code{};

namespace  {
class ErrorCategory : public std::error_category
{
public:
    const char* name() const noexcept override
    {
        return "Errors";
    };
    std::string message(int ev) const override {
        switch (static_cast<Error>(ev)) {
        case ErrorReadKnownHosts: return "Error in read known hosts file";
        case SessionStartupError: return " session startup error";
        case UnexpectedError: return "Unexpected shutdown error";
        case HostKeyInvalidError: return "Host key invalid error";
        case HostKeyMismatchError: return "Host key mismatch error";
        case HostKeyUnknownError: return "Host key unknown error";
        case AuthenticationError: return "Authentication error";
        case FailedToOpenChannel: return "Failed to open channel";
        case FailedToCloseChannel: return "Failed to close channel";
        case ProcessFailedToStart: return "Process failed to start";
        case ConnectionTimeoutError: return "Connection timeout error";
        case TcpConnectionError: return "Tcp connection error";
        case TcpConnectionRefused: return "Tcp connection refused";
        case TryAgain: return "Try again";
        default: return "Unknown error";
        }
    };

} ssh2_error_category;

}

std::error_code QSsh::make_error_code(Error ssh2_error)
{
    return std::error_code(static_cast<int>(ssh2_error), ssh2_error_category);
}

QString QSsh::defaultUser()
{
    return QString::fromLocal8Bit(qgetenv("USER"));
}

QString QSsh::defaultKey()
{
    return QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.ssh/id_rsa";
}

QString QSsh::defaultKnownHosts()
{
    return QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.ssh/known_hosts";
}

bool Settings::isPasswordAuth() const
{
    return !passphrase.isEmpty();
}

bool Settings::isKeyAuth() const
{
    return !isPasswordAuth();
}
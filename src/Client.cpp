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

#include "QSsh/Client.h"

#include "QSsh/Channel.h"
#include "QSsh/Process.h"
#include "QSsh/Debug.h"

//Qt includes
#include <QTimer>
#include <QHostAddress>

//LibSSH2 includes
#include "libssh2.h"

using namespace QSsh;

namespace  {

std::atomic<size_t> ssh2_initializations_count(0);

void initialize() {
    if (ssh2_initializations_count == 0)
        libssh2_init(0);
    ssh2_initializations_count++;
};

void free() {
    if (ssh2_initializations_count == 1)
        libssh2_exit();
    if (ssh2_initializations_count > 0)
        ssh2_initializations_count--;
};

ssize_t libssh_recv(int socket,void *buffer, size_t length,int flags, void **abstract){
    Q_UNUSED(socket);
    Q_UNUSED(flags);
    QTcpSocket* const tcp_socket = reinterpret_cast<QTcpSocket*>(*abstract);
    char* const data = reinterpret_cast<char*>(buffer);
    ssize_t result = tcp_socket->read(data, length);
    if(result == 0)
        result = -EAGAIN;
    return result;
}

ssize_t libssh_send(int socket, const void *buffer, size_t length, int flags, void **abstract){
    Q_UNUSED(socket);
    Q_UNUSED(flags);
    QTcpSocket* const tcp_socket = reinterpret_cast<QTcpSocket*>(*abstract);
    const char* const data = reinterpret_cast<const char*>(buffer);
    ssize_t result = tcp_socket->write(data, length);
    if(result == 0)
        result = -EAGAIN;
    return result;
}

}

Client::Client(Settings ssh2_settings,
                       QObject* parent)
    : QTcpSocket(parent)
    , ssh2_settings_(std::move(ssh2_settings))
    , ssh2_state_(SessionStates::NotEstableshed)
    , ssh2_auth_method_(AuthMethods::NoAuth)
    , last_error_(ssh2_success)
    , ssh2_session_(nullptr)
    , known_hosts_(nullptr)
{
    connect(this, &QTcpSocket::connected, this, &Client::onTcpConnected);
    connect(this, &QTcpSocket::disconnected, this, &Client::onTcpDisconnected);
    connect(this, &QTcpSocket::readyRead, this, &Client::onReadyRead);
    connect(this, &QTcpSocket::stateChanged, this, &Client::onSocketStateChanged);

    initialize();
}

Client::~Client()
{
    closeSession();
    if (state() == ConnectedState)
        waitForDisconnected();
    free();
}

Client::SessionStates Client::sessionState() const
{
    return ssh2_state_;
}

void Client::closeChannels()
{
    for (Channel* ssh2_channel : getChannels()) {
        ssh2_channel->close();
    }
}

void Client::closeSession()
{
    if (ssh2_state_ != FailedToEstablshed)
        setSessionState(Closed);
}

void Client::checkConnection()
{
    if (state() != QAbstractSocket::ConnectedState) {
        setSessionState(FailedToEstablshed, Error::ConnectionTimeoutError);
    }
}

void Client::disconnectFromHost()
{
    if (state() == QAbstractSocket::UnconnectedState)
        return;
    switch (ssh2_state_) {
    case Established:
    {
        if (openChannelsCount() > 0) {
            setSessionState(Closing);
        } else {
            setSessionState(Closed);
        }
    }
        break;
    case Closing:
        destroyObjects();
        break;
    default:;
    }
}

void Client::onTcpConnected()
{
    std::error_code error_code = createObjects();
    if (!error_code)
        error_code = startSshSession();
    if (!checkError(error_code))
        setSessionState(FailedToEstablshed, error_code);
}

void Client::onTcpDisconnected()
{
    if (ssh2_state_ != Closed)
        setSessionState(Aborted, Error::TcpConnectionRefused);
}

std::error_code Client::startSshSession()
{
    std::error_code error_code = ssh2_success;
    const qintptr socket_descriptor = socketDescriptor();
    if (socket_descriptor == -1) {
        setSessionState(SessionStates::FailedToEstablshed, Error::SessionStartupError);
        return error_code;
    }

    int ssh2_method_result = libssh2_session_startup(ssh2_session_,
                                                     socket_descriptor);
    switch (ssh2_method_result) {
    case LIBSSH2_ERROR_EAGAIN:
        setSessionState(SessionStates::StartingSession);
        error_code = Error::TryAgain;
        break;
    case 0:
        error_code = checkKnownHosts();
        if (!error_code)
            error_code = getAvailableAuthMethods();
        break;
    default:
        error_code = Error::SessionStartupError;
    }

    if (!checkError(error_code)) {
        debugError(ssh2_method_result);
    }

    return error_code;
}

void Client::onReadyRead()
{
    std::error_code error_code = ssh2_success;
    switch (ssh2_state_) {
    case SessionStates::StartingSession:
        error_code = startSshSession();
        break;
    case SessionStates::GetAuthMethods:
        error_code = getAvailableAuthMethods();
        break;
    case SessionStates::Authentication:
        error_code = authenticate();
        break;
    case SessionStates::Established:
    case SessionStates::Closing:
        for (Channel* ssh2_channel : getChannels()) {
            ssh2_channel->checkIncomingData();
        }
        break;
    default:;
    }

    if (ssh2_state_ != SessionStates::Established &&
        !checkError(error_code))
    {
        setSessionState(SessionStates::FailedToEstablshed, error_code);
    }
}

void Client::onChannelStateChanged(int state)
{
    switch (static_cast<Channel::ChannelStates>(state)) {
    case Channel::Closed:
    case Channel::Opened:
    case Channel::FailedToOpen:
        emit openChannelsCountChanged(openChannelsCount());
        break;
    default:;
    }
    if (ssh2_state_ == Closing && openChannelsCount() == 0)
        setSessionState(Closed);
}

void Client::onSocketStateChanged(const QAbstractSocket::SocketState& state)
{
    switch (state) {
    case QAbstractSocket::UnconnectedState:
        if (ssh2_state_ != NotEstableshed) {
            setSessionState(FailedToEstablshed, Error::TcpConnectionError);
        }
        break;
    case QAbstractSocket::ConnectingState:
        QTimer::singleShot(ssh2_settings_.timeout, this, &Client::checkConnection);
        break;
    default:;
    }
}

void Client::addChannel(Channel* channel)
{
    disconnect(channel);
    emit channelsCountChanged(channelsCount());
    connect(channel, &Channel::channelStateChanged, this, &Client::onChannelStateChanged);
    connect(channel, &Channel::destroyed, [this](QObject*){
        emit channelsCountChanged(channelsCount());
    });
}

QList<Channel*> Client::getChannels() const
{
    return findChildren<Channel*>();
}

void Client::destroyObjects()
{
    for (Channel* channel : getChannels())
        delete channel;

    if (known_hosts_)
        libssh2_knownhost_free(known_hosts_);
    if (ssh2_session_) {
        libssh2_session_disconnect(ssh2_session_, "disconnect");
        libssh2_session_free(ssh2_session_);
    }

    known_hosts_ = nullptr;
    ssh2_session_ = nullptr;
    ssh2_available_auth_methods_.clear();
    ssh2_auth_method_ = AuthMethods::NoAuth;

    if (state() == QTcpSocket::ConnectedState)
        QTcpSocket::disconnectFromHost();
}

std::error_code Client::createObjects()
{
    if (ssh2_session_ && known_hosts_)
        return ssh2_success;

    ssh2_session_ = libssh2_session_init_ex(nullptr, nullptr, nullptr, reinterpret_cast<void*>(this));
    if (ssh2_session_ == nullptr)
        return Error::UnexpectedError;

    libssh2_session_callback_set(ssh2_session_, LIBSSH2_CALLBACK_RECV, reinterpret_cast<void*>(&libssh_recv));
    libssh2_session_callback_set(ssh2_session_, LIBSSH2_CALLBACK_SEND, reinterpret_cast<void*>(&libssh_send));

    known_hosts_ = libssh2_knownhost_init(ssh2_session_);
    if (known_hosts_ == nullptr)
        return Error::UnexpectedError;

    if (ssh2_settings_.isKeyAuth()) {
        const int ssh2_method_result = libssh2_knownhost_readfile(
                    known_hosts_,
                    qPrintable(ssh2_settings_.known_hosts),
                    LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        if (ssh2_method_result < 0)
            return Error::ErrorReadKnownHosts;
    }

    libssh2_session_set_blocking(ssh2_session_, 0);

    return ssh2_success;
}

std::error_code Client::checkKnownHosts() const
{
    if (ssh2_settings_.isPasswordAuth())
        return ssh2_success;
    size_t length;
    int type;
    const char* fingerprint = libssh2_session_hostkey(ssh2_session_, &length, &type);
    if (fingerprint == nullptr)
        return Error::HostKeyInvalidError;

    std::error_code result = ssh2_success;
    if(fingerprint) {
        struct libssh2_knownhost* host = nullptr;
        const int check = libssh2_knownhost_check(known_hosts_,
                                                  qPrintable(peerAddress().toString()),
                                                  (char *)fingerprint,
                                                  length,
                                                  LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                                                  LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                                  &host);

        switch(check){
        case LIBSSH2_KNOWNHOST_CHECK_MATCH:
            result = ssh2_success;
            break;
        case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
            result = Error::HostKeyInvalidError;
            break;
        case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
            result = Error::HostKeyMismatchError;
            break;
        case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
            result = Error::HostKeyUnknownError;
            break;
        }
    }
    return result;
}

std::error_code Client::getAvailableAuthMethods()
{
    std::error_code result = ssh2_success;
    int ssh2_method_result = 0;
    const char* available_list = libssh2_userauth_list(ssh2_session_,
                                                       qPrintable(ssh2_settings_.user),
                                                       ssh2_settings_.user.length());
    if (available_list == nullptr) {
        ssh2_method_result = libssh2_session_last_error(ssh2_session_, nullptr, nullptr, 0);
        if (ssh2_method_result == LIBSSH2_ERROR_EAGAIN) {
            setSessionState(SessionStates::GetAuthMethods);
            return Error::TryAgain;
        }
    }

    if (available_list != nullptr) {
        foreach(QByteArray method, QByteArray(available_list).split(','))
        {
            if (method == "publickey"){
                ssh2_available_auth_methods_ << AuthMethods::PublicKeyAuthentication;
            }
            else if(method == "password"){
                ssh2_available_auth_methods_ << AuthMethods::PasswordAuthentication;
            }
        }
        ssh2_auth_method_ = getAuthenticationMethod(ssh2_available_auth_methods_);
        result = authenticate();
    } else if(ssh2_method_result != 0) {
        result = Error::UnexpectedError;
        debugError(ssh2_method_result);
    }
    return result;
}

Client::AuthMethods Client::getAuthenticationMethod(const QList<AuthMethods>& available_auth_methods) const
{
    AuthMethods result = AuthMethods::NoAuth;
    if (available_auth_methods.isEmpty())
        result = AuthMethods::NoAuth;
    else if(available_auth_methods.contains(AuthMethods::PasswordAuthentication) &&
            ssh2_settings_.isPasswordAuth())
    {
        result = AuthMethods::PasswordAuthentication;
    } else if(available_auth_methods.contains(AuthMethods::PublicKeyAuthentication) &&
              ssh2_settings_.isKeyAuth())
    {
        result = AuthMethods::PublicKeyAuthentication;
    }

    return result;
}

std::error_code Client::authenticate()
{
    std::error_code result = ssh2_success;
    int ssh2_method_result = 0;
    switch (ssh2_auth_method_) {
    case AuthMethods::NoAuth:
        ssh2_method_result = libssh2_userauth_authenticated(ssh2_session_);
        break;
    case AuthMethods::PublicKeyAuthentication:
        ssh2_method_result = libssh2_userauth_publickey_fromfile(
                    ssh2_session_,
                    qPrintable(ssh2_settings_.user),
                    nullptr,
                    qPrintable(ssh2_settings_.key),
                    qPrintable(ssh2_settings_.keyphrase));
        break;
    case AuthMethods::PasswordAuthentication:
        ssh2_method_result = libssh2_userauth_password(
                    ssh2_session_,
                    qPrintable(ssh2_settings_.user),
                    qPrintable(ssh2_settings_.passphrase));
        break;
    }
    switch (ssh2_method_result) {
    case LIBSSH2_ERROR_EAGAIN:
        setSessionState(SessionStates::Authentication);
        result = Error::TryAgain;
        break;
    case 0:
        result = ssh2_success;
        setSessionState(SessionStates::Established);
        break;
    default:
    {
        debugError(ssh2_method_result);
        result = Error::AuthenticationError;
    }
    }

    return result;
}

std::error_code Client::setLastError(const std::error_code& error_code)
{
    if (last_error_ != error_code && error_code != Error::TryAgain) {
        last_error_ = error_code;
        emit ssh2Error(last_error_);
    }
    return error_code;
}

LIBSSH2_SESSION* Client::ssh2Session() const
{
    return ssh2_session_;
}

QPointer<Process> Client::createProcess(const QString& command)
{
    Process* ssh2_process = new Process(command, this);
    addChannel(ssh2_process);
    return ssh2_process;
}

int Client::channelsCount() const
{
    return getChannels().size();
}

int Client::openChannelsCount() const
{
    int result = 0;
    for (Channel* channel : getChannels()) {
        if (channel->isOpen())
            result++;
    }
    return result;
}

void Client::setSessionState(const Client::SessionStates& new_state)
{
    if (ssh2_state_ != new_state) {
        switch (new_state) {
        case Closing:
            closeChannels();
            break;
        case FailedToEstablshed:
        case Closed:
        case Aborted:
            destroyObjects();
            break;
        default:;
        }
        ssh2_state_ = new_state;
        emit sessionStateChanged(new_state);
    }
}

const std::error_code& Client::setSessionState(const SessionStates& new_state,
                                                       const std::error_code& error_code)
{
    setLastError(error_code);
    setSessionState(new_state);
    return error_code;
}

std::error_code QSsh::Client::lastSshError() const
{
    return last_error_;
}

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
#pragma once
#include <QTcpSocket>
#include <QList>
#include <QPointer>

#include "Types.h"

namespace QSsh {
class Process;
class Channel;

class Client final : public QTcpSocket
{
    Q_OBJECT
    Q_ENUMS(SessionStates AuthMethods)
    Q_PROPERTY(SessionStates sessionState READ sessionState NOTIFY sessionStateChanged)
    Q_PROPERTY(int channelsCount READ channelsCount NOTIFY channelsCountChanged)
    Q_PROPERTY(int openChannelsCount READ openChannelsCount NOTIFY openChannelsCountChanged)
public:
    enum AuthMethods {
        NoAuth,
        PublicKeyAuthentication,
        PasswordAuthentication
    };

    enum SessionStates {
        NotEstableshed,
        StartingSession,
        GetAuthMethods,
        Authentication,
        Established,
        FailedToEstablshed,
        Closing,
        Closed,
        Aborted
    };

    Client(Settings ssh2_settings_,
               QObject* parent = nullptr);

    ~Client();

    SessionStates sessionState() const;

    void disconnectFromHost() override;

    LIBSSH2_SESSION* ssh2Session() const;

    QPointer<Process> createProcess(const QString& command);

    int channelsCount() const;
    int openChannelsCount() const;

    std::error_code lastSshError() const;

signals:
    void sessionStateChanged(SessionStates ssh2_state);
    void ssh2Error(std::error_code ssh2_error);

    void openChannelsCountChanged(int openChannelsCount);
    void channelsCountChanged(int openChannelsCount);

private slots:
    void onTcpConnected();
    void onTcpDisconnected();
    void onReadyRead();

    void onChannelStateChanged(int state);

    void onSocketStateChanged(const QAbstractSocket::SocketState& state);

private:
    void addChannel(Channel* channel);
    QList<Channel*> getChannels() const;

    void setSessionState(const SessionStates& new_state);
    const std::error_code& setSessionState(const SessionStates& new_state,
                                               const std::error_code& error_code);

    void destroyObjects();
    std::error_code createObjects();

    std::error_code checkKnownHosts() const;
    std::error_code getAvailableAuthMethods();
    AuthMethods getAuthenticationMethod(const QList<AuthMethods>& available_auth_methods) const;
    std::error_code authenticate();
    std::error_code startSshSession();
    void closeChannels();
    void closeSession();
    void checkConnection();

    std::error_code setLastError(const std::error_code& error_code);

    const Settings ssh2_settings_;
    SessionStates ssh2_state_;

    QList<AuthMethods> ssh2_available_auth_methods_;
    AuthMethods ssh2_auth_method_;

    std::error_code last_error_;

    LIBSSH2_SESSION* ssh2_session_;
    LIBSSH2_KNOWNHOSTS* known_hosts_;
};

};

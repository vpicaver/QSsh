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

#include <QIODevice>

#include "Channel.h"

namespace QSsh {

class Process : public Channel
{
    Q_OBJECT
    Q_ENUMS(ProcessStates)
    Q_PROPERTY(ProcessStates processState READ processState NOTIFY processStateChanged)
public:
    enum ProcessStates {
        NotStarted,
        Starting,
        Started,
        FailedToStart,
        Finishing,
        Finished
    };


    ProcessStates processState() const;
    void checkIncomingData() override;

signals:
    void processStateChanged(ProcessStates processState);

protected:
    Process(const QString& command,
                Client* ssh2_client);

private slots:
    void onChannelStateChanged(const ChannelStates& state);

private:
    void setProcessState(ProcessStates ssh2_process_state);
    std::error_code execProcess();

    const QString command_;
    ProcessStates ssh2_process_state_;

    friend class Client;
};

}

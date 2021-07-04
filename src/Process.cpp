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

#include "Process.h"

#include "Client.h"
#include "Debug.h"

//libssh2
#include "libssh2.h"

using namespace QSsh;

Process::Process(const QString& command, Client* ssh2_client)
    : Channel(ssh2_client)
    , command_(command)
{
    connect(this, &Channel::channelStateChanged, this, &Process::onChannelStateChanged);
}

Process::ProcessStates Process::processState() const
{
    return ssh2_process_state_;
}

void Process::checkIncomingData()
{
    Channel::checkIncomingData();
    if (processState() == Starting) {
        setLastError(execProcess());
    }
}

void Process::setProcessState(ProcessStates ssh2_process_state)
{
    if (ssh2_process_state_ == ssh2_process_state)
        return;

    ssh2_process_state_ = ssh2_process_state;
    emit processStateChanged(ssh2_process_state_);
}

void Process::onChannelStateChanged(const ChannelStates& state)
{
    std::error_code error_code = ssh2_success;
    switch (state) {
    case ChannelStates::Opened:
        error_code = execProcess();
        break;
    case ChannelStates::Closing:
        if (ssh2_process_state_ != FailedToStart)
            setProcessState(Finishing);
        break;
    case ChannelStates::Closed:
        if (ssh2_process_state_ != FailedToStart)
            setProcessState(Finished);
        break;
    case ChannelStates::FailedToOpen:
        setProcessState(FailedToStart);
        error_code = Error::ProcessFailedToStart;
        break;
    default:;
    }
    setLastError(error_code);
}

std::error_code Process::execProcess()
{
    std::error_code error_code = ssh2_success;
    const int ssh2_method_result = libssh2_channel_exec(ssh2Channel(), qPrintable(command_));
    switch (ssh2_method_result) {
    case LIBSSH2_ERROR_EAGAIN:
        setProcessState(Starting);
        error_code = Error::TryAgain;
        break;
    case 0:
        setProcessState(Started);
        break;
    default: {
        setProcessState(FailedToStart);
        debugError(ssh2_method_result);
        error_code = Error::ProcessFailedToStart;
        close();
    }
    }
    return error_code;
}

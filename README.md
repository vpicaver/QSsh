# QSsh
Qt interface to libssh2

Forked code from: https://github.com/synacker/daggy

## Example usage:
```
    QSsh::Settings settings;
    settings.user = "pi";

    QSsh::Client client(settings);

    QEventLoop loop;

    auto runCommand = [&client, &loop]() {
        auto process = client.createProcess("ls -al");

        //See the output of the command
        QObject::connect(process, &QSsh::Process::newChannelData,
                         &loop, [process](QByteArray data, const int stream_id)
        {
            qDebug().noquote() << "id:" << stream_id << data;
        });

        QObject::connect(process, &QSsh::Process::processStateChanged,
                &loop, [&loop, process, &client](QSsh::Process::ProcessStates state)
        {
            //Close the connection once the process has finished
            if(state == QSsh::Process::Finished) {
                qDebug() << "Finished!";

                process->deleteLater();
                client.disconnect();
                loop.quit();
            }
        });

        //Start the process, on the remote
        process->open();
    };

    QObject::connect(&client, &QSsh::Client::sessionStateChanged,
            &loop, [&loop, &client, runCommand](const int state)
    {
       if(state == QSsh::Client::Established) {
           qDebug() << "Running command!";
           runCommand();
       }
    });

    client.connectToHost(QHostAddress("192.168.4.1"), 22);
    client.waitForConnected(3000);

    //All the conncections are async so we need to do it on the event loop
    loop.exec();
```

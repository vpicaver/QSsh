cmake_minimum_required(VERSION 3.14)

project(QSsh LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 COMPONENTS Core Network REQUIRED)
find_package(Libssh2 REQUIRED)

file(GLOB libQSshCPP src/*.cpp)
file(GLOB libQSshH src/QSsh/*.h)
add_library(QSsh STATIC ${libQSshCPP} ${libQSshH})
target_link_libraries(QSsh
    PUBLIC
    Qt5::Core
    Qt5::Network
    Libssh2::Libssh2
    )
target_include_directories(QSsh
    PUBLIC src)

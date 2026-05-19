This framework has been tested with gcc 14. C++23 needed

How to build:
1) Edit file CMakeLists.txt and set the right path for the ASIO_INCLUDE_DIR variable

2) In a terminal:

mkdir build && cd build
If you want the debug version:
	cmake -DCMAKE_BUILD_TYPE=Debug ..
If you want the release version: 
	cmake -DCMAKE_BUILD_TYPE=Release ..

make -j4
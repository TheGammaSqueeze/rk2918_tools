cp out/Image/MiniLoaderAll.bin loader.img
./afptool -pack out update_repacked.img
./img_maker loader.img update_repacked.img release.img

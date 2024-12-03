cd c:\temp

python -m nuitka ^
    --lto=no ^
    --mingw64 ^
    --onefile ^
    --windows-console-mode=disable ^
    --enable-plugin=tk-inter ^
    --windows-icon-from-ico=encryption.ico ^
    --output-filename=hashy_gui.exe ^
    hashy_gui.py
pause
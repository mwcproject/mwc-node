dir "C:\Program Files (x86)"
dir "C:\Program Files (x86)\Microsoft Visual Studio"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

cargo test --all

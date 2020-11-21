dir "C:\Program Files (x86)"
dir "C:\Program Files (x86)\Microsoft Visual Studio"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary"
dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build"

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

cargo test --all

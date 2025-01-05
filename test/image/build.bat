echo =============build ucrtbase example=============
cd ucrtbase
call Build.bat
cd ..

echo ================build Go example================
cd go
call build.bat
cd ..

echo ===============build Rust example===============
cd rust
call build_msvc.bat
call build_gnu.bat
cd ..

echo finished

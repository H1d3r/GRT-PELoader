cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target i686-pc-windows-gnu

move /Y target\x86_64-pc-windows-gnu\release\rust.exe ..\x64\rust_gnu.exe
move /Y target\i686-pc-windows-gnu\release\rust.exe   ..\x86\rust_gnu.exe

rd /S /Q target

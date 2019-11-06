How to downgrade the rust:

at .ci/install.yml

Add for Windows:
      %USERPROFILE%/.cargo/bin/rustup override set 1.37.0

Add for Mac and Linux
      ~/.cargo/bin/rustup override set 1.37.0

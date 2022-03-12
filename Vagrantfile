Vagrant.configure("2") do |config|
    config.vm.box = "ubuntu/impish64"
    config.vm.define :impish64
    config.vm.hostname = "impish64"
    config.vm.synced_folder ".", "/pwru"
    config.vm.provision "shell", inline: <<-SHELL
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y clang-12 golang make
      update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 100
      [ -f /usr/lib/llvm-12/bin/llvm-strip ] && [ -f /usr/local/bin/llvm-strip ] || \
      ln -s /usr/lib/llvm-12/bin/llvm-strip /usr/local/bin/llvm-strip
    SHELL
end

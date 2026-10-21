#
# [FOCSQ] macOS: мост flutter_rust_bridge собирается cargokit'ом (шаблон FRB).
# Статическая библиотека ядра вшивается в фреймворк пода через -force_load.
#
Pod::Spec.new do |s|
  s.name             = 'rust_lib_frontend'
  s.version          = '0.0.1'
  s.summary          = 'FOCSQ core bridge (flutter_rust_bridge).'
  s.description      = <<-DESC
FOCSQ core bridge (flutter_rust_bridge).
                       DESC
  s.homepage         = 'https://github.com/luminescq/focsq'
  s.license          = { :type => 'PolyForm-Noncommercial-1.0.0' }
  s.author           = { 'luminescq' => 'luminescq@users.noreply.github.com' }

  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.15'
  s.swift_version = '5.0'

  s.script_phase = {
    :name => 'Build Rust library',
    # Первый аргумент — путь к крейту моста (frontend/rust), второй — имя библиотеки.
    # PATH с ~/.cargo/bin: Xcode запускает скрипт без профиля оболочки.
    :script => 'export PATH="$HOME/.cargo/bin:$PATH"; sh "$PODS_TARGET_SRCROOT/../cargokit/build_pod.sh" ../../rust rust_lib_frontend',
    :execution_position => :before_compile,
    :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
    # Xcode должен знать, что статическую библиотеку из -force_load создаёт этот шаг.
    :output_files => ["${BUILT_PRODUCTS_DIR}/librust_lib_frontend.a"],
  }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/librust_lib_frontend.a',
  }
  # Системные зависимости staticlib (cargo rustc -- --print native-static-libs):
  # #[link]-директивы Rust в staticlib до финальной линковки не доходят
  s.frameworks = 'SystemConfiguration', 'Security', 'CoreFoundation'
  s.libraries = 'iconv'
end

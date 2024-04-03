set -e

go get golang.org/x/mobile/cmd/gobind
go get golang.org/x/mobile/cmd/gomobile

gomobile init

# Create output directory
mkdir -p ../assets/android
# Update package name and result file to a desired one(.aar)
gomobile bind -target=android -o ../assets/android/mt.aar ../mt

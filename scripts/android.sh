# Works only in MacOS
set -e

go get golang.org/x/mobile/cmd/gobind
go get golang.org/x/mobile/cmd/gomobile

gomobile init

# Create output directory
# Change output (-o) for the created one
# Update path to the package to build 
gomobile bind -target=android -o ../assets/android/mt.aar ../mt

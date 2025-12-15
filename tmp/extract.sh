mkdir tmp

for i in {1..5}; do
    find . -name "*.zip" -print0 | while read -d $'\0' file; do
        echo $file
        unzip -d tmp -o "$file"
        rm -f "$file"
    done
done

mkdir stigs
find . -name 'U*xccdf.xml' -print0 | while read -d $'\0' file; do
    cp "$file" ./stigs/
done

rm -rf tmp

mv ./stigs/U*xccdf.xml ../benchmarks/DISA/
rm -rf stigs

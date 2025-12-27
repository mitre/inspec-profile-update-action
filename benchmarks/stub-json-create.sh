#!/bin/bash

search_dir="."

find "$search_dir" -type f -name "*.xml" | while read xml_file; do
    base_name=$(basename "$xml_file" -xccdf.xml)
    base_name=${base_name%_Manual}
    new_folder="../inspec_stubs/${base_name}"

    saf generate xccdf_benchmark2inspec_stub -i "$xml_file" -o "$new_folder"
done

inspec_stubs_dir="../inspec_stubs"
for folder in "$inspec_stubs_dir"/*; do
    if [ -d "$folder" ]; then
        folder_name=$(basename "$folder")
        json_file_name="${folder_name}.json"

        cinc-auditor json "$folder" > "../json/$json_file_name"
    fi
done

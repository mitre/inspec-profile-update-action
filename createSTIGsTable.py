import json

# Open the JSON file

data = []
with open('stigs.json') as json_file:
    data = json.load(json_file)

def genAction(id: str):
    return f"""
on: [push]

jobs:
  test_action:
    runs-on: ubuntu-latest
    name: Test inpec-profile-update action
    steps:
      # To use this repository's private action,
      # you must check out the repository
      - name: Checkout
        uses: actions/checkout@v3
      # Update profile
      - name: Updates profile
        uses: mitre/inspec-profile-update-action@main
        # Set env variables
        env:
          profile: {id}
      # Create new branch
      - name: Push changes to new PR
        uses: peter-evans/create-pull-request@v4
        with:
          branch: update-profile
          delete-branch: true"""

for stig in data:
    yml = genAction(stig['id'])

    with open(f"actions/{stig['id']}.yml", "w") as f:
        f.write(yml)

html = ""

html += """
<html>
    <head>
        <link rel="stylesheet" href="site/styles.css">
        <title>STIGs List</title>
    </head>
<table>"""

html += "<tr><th>STIG ID</th><th>Name</th><th>Version</th><th>URL</th><th>Size</th><th>Action</th></tr>"
for stig in data:
    html += f"""
    <tr>
        <td>{stig['id']}</td>
        <td>{stig['name']}</td>
        """
    if 'version' in stig:
        html += f"""<td>{stig['version']}</td>"""
    else:
        html += f"""<td></td>"""
    html += f"""
        <td><a href="{stig['url']}">Download</a></td>
        <td>{stig['size']}</td>
        <td><a href="actions/{stig['id']}.yml">Download Action</a></td>
    </tr>"""
html += "</table>"

with open("index.html", "w") as f:
    f.write(html)
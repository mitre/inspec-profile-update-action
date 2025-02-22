control 'SV-251557' do
  title 'Firefox must be configured to disable the installation of extensions.'
  desc 'A browser extension is a program that has been installed into the browser to add functionality. Where a plug-in interacts only with a web page and usually a third-party external application (e.g., Flash, Adobe Reader), an extension interacts with the browser program itself. Extensions are not embedded in web pages and must be downloaded and installed in order to work. Extensions allow browsers to avoid restrictions that apply to web pages. 

For example, an extension can be written to combine data from multiple domains and present it when a certain page is accessed, which can be considered cross-site scripting. If a browser is configured to allow unrestricted use of extensions, plug-ins can be loaded and installed from malicious sources and used on the browser.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "InstallAddonsPermission" is not displayed under Policy Name or the Policy Value is not "Default" "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Addons
Policy Name: Allow add-on installs from websites
Policy State: Disabled

macOS "plist" file:
Add the following:
<key>InstallAddonsPermission</key>
<false/>

Linux "policies.json" file:
Add the following in the policies section:
"InstallAddonsPermission": {
      "Default": false
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54992r807141_chk'
  tag severity: 'medium'
  tag gid: 'V-251557'
  tag rid: 'SV-251557r879587_rule'
  tag stig_id: 'FFOX-00-000013'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54946r820751_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

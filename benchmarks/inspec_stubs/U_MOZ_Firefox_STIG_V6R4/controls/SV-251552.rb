control 'SV-251552' do
  title 'Firefox must be configured to not use a password store with or without a master password.'
  desc 'Firefox can be set to store passwords for sites visited by the user. These individual passwords are stored in a file and can be protected by a master password. Autofill of the password can then be enabled when the site is visited. This feature could also be used to autofill the certificate PIN, which could lead to compromise of DoD information.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "PasswordManagerEnabled" is not displayed under Policy Name or the Policy Value is not "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: PasswordManager
Policy State: Disabled

macOS "plist" file:
Add the following:
<key>PasswordManagerEnabled</key>
<false/>

Linux "policies.json" file:
Add the following in the policies section:
"PasswordManagerEnabled": false'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54987r807126_chk'
  tag severity: 'medium'
  tag gid: 'V-251552'
  tag rid: 'SV-251552r822411_rule'
  tag stig_id: 'FFOX-00-000008'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54941r822410_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

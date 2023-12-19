control 'SV-251571' do
  title 'Firefox deprecated ciphers must be disabled.'
  desc 'A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.'
  desc 'check', 'Type "about:policies" in the browser address bar.

If "DisabledCiphers" is not displayed under Policy Name or the Policy Value is not "TLS_RSA_WITH_3DES_EDE_CBC_SHA" with a value of  "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Disabled Ciphers
Policy Name: TLS_RSA_WITH_3DES_EDE_CBC_SHA
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>DisabledCiphers</key>
  <dict>
    <key>TLS_RSA_WITH_3DES_EDE_CBC_SHA</key>
    <true/>
  </dict>

Linux "policies.json" file:
Add the following in the policies section:
"DisabledCiphers": {
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA": true
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55006r820760_chk'
  tag severity: 'medium'
  tag gid: 'V-251571'
  tag rid: 'SV-251571r820762_rule'
  tag stig_id: 'FFOX-00-000027'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54960r820761_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

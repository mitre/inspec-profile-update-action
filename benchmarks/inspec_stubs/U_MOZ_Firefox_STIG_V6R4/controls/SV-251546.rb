control 'SV-251546' do
  title 'Firefox must be configured to allow only TLS 1.2 or above.'
  desc 'Use of versions prior to TLS 1.2 are not permitted. SSL 2.0 and SSL 3.0 contain a number of security flaws. These versions must be disabled in compliance with the Network Infrastructure and Secure Remote Computing STIGs.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "SSLVersionMin" is not displayed under Policy Name or the Policy Value is not "tls1.2" or "tls1.3", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Minimum SSL version enabled
Policy State: Enabled
Policy Value: TLS 1.2   (or TLS 1.3)

macOS "plist" file:
Add the following:
<key>SSLVersionMin</key>
<string>tls1.2</string>   (or <string>tls1.3</string>)

Linux "policies.json" file:
Add the following in the policies section:
"SSLVersionMin": "tls1.2"   or ("SSLVersionMin": "tls1.3")'
  impact 0.7
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54981r820743_chk'
  tag severity: 'high'
  tag gid: 'V-251546'
  tag rid: 'SV-251546r820745_rule'
  tag stig_id: 'FFOX-00-000002'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-54935r820744_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end

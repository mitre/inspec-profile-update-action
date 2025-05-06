control 'SV-89951' do
  title 'Adobe Acrobat Pro XI access to websites must be blocked.'
  desc 'PDF files can contain URLs that initiate connections to websites in order to share or get information. Any Internet access introduces a security risk as malicious websites can transfer harmful content or silently gather data.'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following:
HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cDefaultLaunchURLPerms\\

Value Name: iURLPerms
Type: REG_DWORD
Value: 1

If the value for iURLPerms is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cDefaultLaunchURLPerms\\

Value Name: iURLPerms
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75055r2_chk'
  tag severity: 'low'
  tag gid: 'V-75271'
  tag rid: 'SV-89951r1_rule'
  tag stig_id: 'ADBP-XI-000285'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81887r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-89949' do
  title 'Adobe Acrobat Pro XI access to unknown websites must be restricted.'
  desc 'Acrobat provides the ability for the user to store a list of websites with an associated behavior of allow, ask, or block. Websites that are not in this list are unknown. PDF files can contain URLs that will initiate connections to unknown websites in order to share or get information. That access must be restricted.'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following:
HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cDefaultLaunchURLPerms\\

Value Name: iUnknownURLPerms
Type: REG_DWORD
Value: 3

If the value for iUnknownURLPerms is not set to “3” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cDefaultLaunchURLPerms\\

Value Name: iUnknownURLPerms
Type: REG_DWORD
Value: 3'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75053r3_chk'
  tag severity: 'low'
  tag gid: 'V-75269'
  tag rid: 'SV-89949r1_rule'
  tag stig_id: 'ADBP-XI-000280'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81885r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

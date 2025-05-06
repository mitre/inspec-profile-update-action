control 'SV-29379' do
  title 'Group Policy objects are not reprocessed if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\\

Value Name:  NoGPOListChanges

Type:  REG_DWORD
Value:  0

Windows Server 2008 may also have the value under {B087BE9D-ED37-454F-AF9C-04291E351182} which is from another setting with the same title however with capitalized first letters (Registry Policy Processing vs. Registry policy processing).  This other setting is related to Group Policy Preference Client Side Extensions.  The correct registry path for this requirement is the one listed above.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> “Registry policy processing” to “Enabled”, and select the option “Process even if the Group Policy objects have not changed”.

Windows Server 2008 has another policy setting in this area with the same title however with the first letters capitalized (Registry Policy Processing vs. Registry policy processing).  The correct version for this requirement is the one that uses lower case.  The other one can also be verified by viewing the Explain tab of the policy which will state “Registry Client-Side Extension (CSE) policy processing settings”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-39114r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4448'
  tag rid: 'SV-29379r2_rule'
  tag gtitle: 'Group Policy - Registry Policy Processing'
  tag fix_id: 'F-34259r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-29283' do
  title 'The system is configured to allow unsolicited remote assistance offers.'
  desc 'This setting controls whether unsolicited offers of help to this computer are allowed.  The list of users allowed to offer remote assistance to this system is accessed by pressing the Helpers button.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:	fAllowUnsolicited
Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the system to prevent unsolicited remote assistance offers by setting the policy value for Computer
Configuration -> Administrative Templates -> System -> Remote Assistance “Offer Remote Assistance” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-29882r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3470'
  tag rid: 'SV-29283r1_rule'
  tag gtitle: 'Remote Assistance - Offer Remote Assistance'
  tag fix_id: 'F-6776r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end

control 'SV-226295' do
  title 'Unencrypted passwords must not be sent to third-party SMB Servers.'
  desc 'Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the vendor of the SMB server to see if there is a way to support encrypted password authentication.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name:  EnablePlainTextPassword

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27997r476729_chk'
  tag severity: 'medium'
  tag gid: 'V-226295'
  tag rid: 'SV-226295r794528_rule'
  tag stig_id: 'WN12-SO-000030'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-27985r476730_fix'
  tag 'documentable'
  tag legacy: ['SV-52861', 'V-1141']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end

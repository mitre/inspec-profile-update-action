control 'SV-205863' do
  title 'Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials.'
  desc 'An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation of non-exportable credentials providing additional protection of the credentials.  Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\

Value Name: AllowProtectedCreds

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> "Remote host allows delegation of non-exportable credentials" to "Enabled".'
  impact 0.5
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-6128r355951_chk'
  tag severity: 'medium'
  tag gid: 'V-205863'
  tag rid: 'SV-205863r569188_rule'
  tag stig_id: 'WN19-CC-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6128r355952_fix'
  tag 'documentable'
  tag legacy: ['V-93243', 'SV-103331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

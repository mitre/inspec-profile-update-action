control 'SV-254342' do
  title 'Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials.'
  desc 'An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host. Restricted Admin mode or Remote Credential Guard allow delegation of nonexportable credentials providing additional protection of the credentials. Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\

Value Name: AllowProtectedCreds

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> Remote host allows delegation of nonexportable credentials to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57827r848840_chk'
  tag severity: 'medium'
  tag gid: 'V-254342'
  tag rid: 'SV-254342r848842_rule'
  tag stig_id: 'WN22-CC-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57778r848841_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-238029' do
  title 'The encryption type for password protected Office 97 thru Office 2003 must be set.'
  desc '<0> [object Object]'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Encryption type for password protected Office 97-2003 files" is set to "Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security

Criteria: If the value DefaultEncryption12 is REG_SZ = "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Encryption type for password protected Office 97-2003 files" to "Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41239r650652_chk'
  tag severity: 'medium'
  tag gid: 'V-238029'
  tag rid: 'SV-238029r650654_rule'
  tag stig_id: 'DTOO190'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-41198r650653_fix'
  tag legacy: ['SV-85491', 'V-70867']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

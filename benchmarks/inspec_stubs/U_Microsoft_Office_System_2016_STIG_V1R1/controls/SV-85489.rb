control 'SV-85489' do
  title 'The encryption type for password protected Open XML files must be set.'
  desc '<0> [object Object]'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Encryption type for password protected Office Open XML files" is set to "Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security

Criteria: If the value OpenXMLEncryption is REG_SZ = "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "Encryption type for password protected Office Open XML files" to "Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71309r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70865'
  tag rid: 'SV-85489r1_rule'
  tag stig_id: 'DTOO189'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-77197r1_fix'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

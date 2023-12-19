control 'SV-33457' do
  title 'The encryption type for password protected Office 97 thru Office 2003 must be set.'
  desc 'If unencrypted files are intercepted, sensitive information in the files can be compromised. To protect information confidentiality, Microsoft Office application files can be encrypted and password protected. Only users who know the correct password will be able to decrypt such files.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Encryption type for password protected Office 97-2003 files” must be set to “Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security

Criteria: If the value DefaultEncryption12 is REG_SZ = “Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Encryption type for password protected Office 97-2003 files” to “Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33940r3_chk'
  tag severity: 'medium'
  tag gid: 'V-17617'
  tag rid: 'SV-33457r2_rule'
  tag stig_id: 'DTOO190 - Office System'
  tag gtitle: 'DTOO190 - Encr. type for Password Protected files'
  tag fix_id: 'F-29629r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

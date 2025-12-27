control 'SV-228549' do
  title 'The encryption type for password protected Office 97 thru Office 2003 must be set.'
  desc 'If unencrypted files are intercepted, sensitive information in the files can be compromised. To protect information confidentiality, Microsoft Office application files can be encrypted and password protected. Only users who know the correct password will be able to decrypt such files. Since some encryption types are less secure and easier to breach, Microsoft Enhanced RSA and AES Cryptographic Provider, AES-256, 256-bit should be used when encrypting documents.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Encryption type for password protected Office 97-2003 files" is set to "Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider, AES 256,256)".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\security

If the value 'DefaultEncryption12' is REG_SZ = "Microsoft Enhanced RSA and AES Cryptographic Provider, AES 256,256", this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Encryption type for password protected Office 97-2003 files" to "Enabled (Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30782r498925_chk'
  tag severity: 'medium'
  tag gid: 'V-228549'
  tag rid: 'SV-228549r508020_rule'
  tag stig_id: 'DTOO190'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-30767r498967_fix'
  tag 'documentable'
  tag legacy: ['SV-52727', 'V-17617']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

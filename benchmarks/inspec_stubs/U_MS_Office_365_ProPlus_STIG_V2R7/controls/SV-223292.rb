control 'SV-223292' do
  title 'Office applications must be configured to specify encryption type in password-protected Office Open XML files.'
  desc '<0> [object Object]'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings >> Encryption type for password protected Office Open XML files is set to Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256.
 
Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security

If the value OpenXMLEncryption is REG_SZ = "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings >> Encryption type for password protected Office Open XML files to Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24965r442095_chk'
  tag severity: 'medium'
  tag gid: 'V-223292'
  tag rid: 'SV-223292r508019_rule'
  tag stig_id: 'O365-CO-000009'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-24953r442096_fix'
  tag legacy: ['SV-108761', 'V-99657']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

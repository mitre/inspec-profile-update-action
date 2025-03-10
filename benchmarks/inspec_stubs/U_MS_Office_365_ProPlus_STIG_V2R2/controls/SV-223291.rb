control 'SV-223291' do
  title 'Office applications must be configured to specify encryption type in password-protected Office 97-2003 files.'
  desc '<0> [object Object]'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings >> Encryption type for password protected Office 97-2003 files is set to Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256.
 
Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security

If the value defaultencryption12 is set to REG_SZ = "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings >> Encryption type for password protected Office 97-2003 files to Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24964r442092_chk'
  tag severity: 'medium'
  tag gid: 'V-223291'
  tag rid: 'SV-223291r508019_rule'
  tag stig_id: 'O365-CO-000008'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-24952r442093_fix'
  tag legacy: ['SV-108759', 'V-99655']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

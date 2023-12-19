control 'SV-223254' do
  title 'SharePoint must employ NSA-approved cryptography to protect classified information.'
  desc 'Certain encryption types are no longer considered secure. This setting configures a minimum encryption type for SharePoint. Different versions of the Windows Server OS and versions of SharePoint will have different suites available.'
  desc 'check', 'Review the SharePoint server configuration to ensure NSA-approved cryptography is employed to protect classified information.

Open Registry Editor.

Navigate to "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002".

If  the REG_SZ "Functions" value does not exist, this is a finding.

Open the REG_SZ "Functions" value.

If any DES or RC4 cipher suites exist in the text string, this is a finding.'
  desc 'fix', 'Configure SharePoint to employ NSA-approved cryptography to protect classified information.

Open MMC.

Click “File”, “Add/Remove Snap-in”, and “add Group Policy Object Editor”.

Enter a name for the Group Policy Object, or accept the default.

Click “Finish”.

Click “OK”.

Navigate to Computer Policy >> Computer Configuration >> Administrative Templates >> Network >> SSL Configuration Settings.

Right-click “SSL Configuration Settings”, click “SSL Cipher Suite Order”, and then click “Edit”.

In the “SSL Cipher Suite Order” dialog box, select "Enabled".

Under “Options”, in the “SSL Cipher Suites” text box, enter desired cipher suites that are not DES or RC4.

Click “OK”.'
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24927r821360_chk'
  tag severity: 'high'
  tag gid: 'V-223254'
  tag rid: 'SV-223254r821362_rule'
  tag stig_id: 'SP13-00-000095'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-24915r821361_fix'
  tag 'documentable'
  tag legacy: ['SV-74399', 'V-59969']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end

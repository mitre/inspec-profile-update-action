control 'SV-223252' do
  title 'SharePoint must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'Certain encryption types are no longer considered secure. This setting configures a minimum encryption type for SharePoint. Different versions of the Windows Server OS and versions of SharePoint will have different suites available.'
  desc 'check', 'Review the SharePoint server configuration to ensure required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance are implemented.

Open Registry Editor.

Navigate to "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002".

If  the REG_SZ "Functions" value does not exist, this is a finding.

Open the REG_SZ "Functions" value.

If any DES or RC4 cipher suites exist in the text string, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

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
  tag check_id: 'C-24925r821357_chk'
  tag severity: 'high'
  tag gid: 'V-223252'
  tag rid: 'SV-223252r821359_rule'
  tag stig_id: 'SP13-00-000085'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-24913r821358_fix'
  tag 'documentable'
  tag legacy: ['SV-74395', 'V-59965']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end

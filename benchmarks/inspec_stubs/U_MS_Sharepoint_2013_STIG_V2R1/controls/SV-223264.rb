control 'SV-223264' do
  title 'SharePoint must use mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc 'Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for SharePoint. Different versions of the Windows Server OS, and versions of SharePoint will have different suites available.'
  desc 'check', 'Review the SharePoint server configuration to ensure mechanisms are used for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.

Open MMC.

Click "File", "Add/Remove Snap-in", and "add Group Policy Object Editor".

Enter a name for the Group Policy Object, or accept the default.

Click "Finish".

Click "OK".

Navigate to Computer Policy >> Computer Configuration >> Administrative Templates >> Network >> SSL Configuration settings.

Right-click "SSL Configuration Settings", click "SSL Cipher Suite Orde"r, click "Edit".

In the "SSL Cipher Suite Order" dialog box, if "Enabled" is not selected, this is a finding.

Under Options, in the "SSL Cipher Suites" text box, a list of cipher suites will be displayed.

If any DES or RC4 cipher suites exist in the list, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to use mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.

Open MMC.

Click “File”, “Add/Remove Snap-in”, and “add Group Policy Object Editor”.

Enter a name for the Group Policy Object, or accept the default.

Click “Finish”.

Click “OK”.

Navigate to Computer Policy >> Computer Configuration >> Administrative Templates >> Network >> SSL Configuration settings.

Right-click “SSL Configuration Settings”, click “SSL Cipher Suite Order”, and then click “Edit”.

In the “SSL Cipher Suite Order” dialog box, select "Enabled" option.

Under “Options”, in the “SSL Cipher Suites” text box, enter desired cipher suites that are not DES or RC4.

Click “OK”.'
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24937r430849_chk'
  tag severity: 'high'
  tag gid: 'V-223264'
  tag rid: 'SV-223264r612235_rule'
  tag stig_id: 'SP13-00-000145'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-24925r430850_fix'
  tag 'documentable'
  tag legacy: ['V-59989', 'SV-74419']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end

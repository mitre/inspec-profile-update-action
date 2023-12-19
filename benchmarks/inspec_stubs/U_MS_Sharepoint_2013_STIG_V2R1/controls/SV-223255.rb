control 'SV-223255' do
  title 'SharePoint must employ FIPS-validated cryptography to protect unclassified information when such information must be separated from individuals who have the necessary clearances yet lack the necessary access approvals.'
  desc 'Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for SharePoint. Different versions of the Windows Server OS, and versions of SharePoint will have different suites available.'
  desc 'check', 'Review the SharePoint server configuration to ensure FIPS-validated cryptography is employed to protect unclassified information when such information must be separated from individuals who have the necessary clearances yet lack the necessary access approvals.

Open MMC.

Click "File", "Add/Remove Snap-in", and "add Group Policy Object Editor".

Enter a name for the Group Policy Object, or accept the default.

Click "Finish".

Click "OK".

Navigate to Computer Policy >> Computer Configuration >> Administrative Templates >> Network >> SSL Configuration settings.

Right-click "SSL Configuration Settings", click "SSL Cipher Suite Order", click "Edit".

In the "SSL Cipher Suite Order" dialog box, if "Enabled" is not selected, this is a finding.

Under Options, in the "SSL Cipher Suites" text box, a list of cipher suites will be displayed.

If any DES or RC4 cipher suites exist in the list, this is a finding.'
  desc 'fix', 'Configure SharePoint to employ FIPS-validated cryptography to protect unclassified information when such information must be separated from individuals who have the necessary clearances yet lack the necessary access approvals.

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
  tag check_id: 'C-24928r430825_chk'
  tag severity: 'high'
  tag gid: 'V-223255'
  tag rid: 'SV-223255r612235_rule'
  tag stig_id: 'SP13-00-000100'
  tag gtitle: 'SRG-APP-000555'
  tag fix_id: 'F-24916r430826_fix'
  tag 'documentable'
  tag legacy: ['V-59971', 'SV-74401']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end

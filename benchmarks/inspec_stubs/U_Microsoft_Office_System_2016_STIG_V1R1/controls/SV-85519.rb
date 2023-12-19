control 'SV-85519' do
  title 'The ability to run unsecure Office web add-ins and Catalogs must be disabled.'
  desc "This policy setting allows users to run unsecure web add-in, which are add-ins that have web page or catalog locations that are not SSL-secured (https://), and are not in users' Internet zones. If you enable this policy setting, users can run unsecure apps. To enable specific unsecure web add-ins, you must also configure the Trusted Web add-in Catalog policy settings to trust the catalogs that contains those Add-ins. If you disable or do not configure this policy setting, unsecure web add-ins are not allowed."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings -> Trust Center -> Trusted Catalogs "Allow Unsecure web add-ins and Catalogs" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\wef\\trustedcatalogs

Criteria: If the value requireserververification is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings -> Trust Center -> Trusted Catalogs "Allow Unsecure web add-ins and Catalogs" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71339r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70895'
  tag rid: 'SV-85519r1_rule'
  tag stig_id: 'DTOO412'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

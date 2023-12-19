control 'SV-85351' do
  title 'Untrusted intranet zone access to Project servers must not be allowed.'
  desc 'Allows users to access Project Server Web sites and Workspaces that have not been added to their trusted internet zones. If you enable this setting, users can access Project Server and Microsoft SharePoint Foundation sites that are not in their trusted internet zones. If this setting is disabled or not configured, users are required to add the Project Server and Microsoft SharePoint Foundation sites to their trusted internet site zones.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2016 -> Project Options -> Security "Enable untrusted intranet zone access to Project server" is set to "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\ms project\\security

Criteria: If the value TrustWSS is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2016 -> Project Options -> Security "Enable untrusted intranet zone access to Project server" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Project 2016'
  tag check_id: 'C-71211r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70727'
  tag rid: 'SV-85351r1_rule'
  tag stig_id: 'DTOO346'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end

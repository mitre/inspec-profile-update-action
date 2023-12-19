control 'SV-86265' do
  title 'Files on local Intranet UNC must be opened in Protected View.'
  desc 'This policy setting lets you determine if files on local Intranet UNC file shares open in Protected View. If you enable this policy setting, files on local Intranet UNC file shares open in Protected View if their UNC paths appear to be within the Internet zone. If you disable or do not configure this policy setting, files on Intranet UNC file shares do not open in Protected View if their UNC paths appear to be within the Internet zone.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Open files on local Intranet UNC in Protected View" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\protectedview

Criteria: If the value DisableIntranetCheck is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Open files on local Intranet UNC in Protected View" is set to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71641'
  tag rid: 'SV-86265r1_rule'
  tag stig_id: 'DTOO605'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77967r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end

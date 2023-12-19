control 'SV-85707' do
  title 'Document behavior if file validation fails must be set.'
  desc 'This policy setting controls how Office handles documents when they fail file validation. If you enable this policy setting, you can configure the following options for files that fail file validation:- Block files completely. Users cannot open the files.- Open files in Protected View and disallow edit. Users cannot edit the files. This is also how Office handles the files if you disable this policy setting.- Open files in Protected View and allow edit. Users can edit the files. This is also how Office handles the files if you do not configure this policy setting.If you disable this policy setting, Office follows the "Open files in Protected View and disallow edit" behavior. If you do not configure this policy setting, Office follows the "Open files in Protected View and allow edit" behavior.'
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Security -> Trust Center -> Protected View "Set document behavior if file validation fails" is set to "Disabled". The option 'Enabled: Open in Protected View' and Unchecked for 'Do not allow edit' is also an acceptable value.   

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation

 Criteria: If the value openinprotectedview does not exist, this is not a finding. If the value is REG_DWORD = 1, this is not a finding. 

If the value DisableEditFromPV is set to REG_DWORD = 1, this is not a finding.  If the value is set to REG_DWORD = 0, this is a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Security -> Trust Center -> Protected View "Set document behavior if file validation fails" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2016'
  tag check_id: 'C-71511r5_chk'
  tag severity: 'medium'
  tag gid: 'V-71083'
  tag rid: 'SV-85707r1_rule'
  tag stig_id: 'DTOO292'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end

control 'SV-235935' do
  title 'Oracle WebLogic must provide access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged.'
  desc 'In order to be able to provide a forensic history of activity, the application server must ensure users who are granted a privileged role or those who utilize a separate distinct account when accessing privileged functions or data have their actions logged.

If privileged activity is not logged, no forensic logs can be used to establish accountability for privileged actions that occur on the system.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, ensure that the comma-delimited list of privileged users (e.g., WebLogic, etc.) is set in the 'Users to Always Audit' field

If all privileged users are not listed in the 'Users to Always Audit' field, this is a finding."
  desc 'fix', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, enter the comma-delimited list of privileged users (e.g., WebLogic, etc.) in the 'Users to Always Audit' field. Click 'Apply'"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39154r628581_chk'
  tag severity: 'medium'
  tag gid: 'V-235935'
  tag rid: 'SV-235935r628583_rule'
  tag stig_id: 'WBLC-01-000030'
  tag gtitle: 'SRG-APP-000504-AS-000229'
  tag fix_id: 'F-39117r628582_fix'
  tag 'documentable'
  tag legacy: ['SV-70473', 'V-56219']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

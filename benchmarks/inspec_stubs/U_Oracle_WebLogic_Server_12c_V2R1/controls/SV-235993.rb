control 'SV-235993' do
  title 'Oracle WebLogic must identify potentially security-relevant error conditions.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the application server is able to identify and handle error conditions is guided by organizational policy and operational requirements. Adequate logging levels and system performance capabilities need to be balanced with data protection requirements. 

Application servers must have the capability to log at various levels which can provide log entries for potential security-related error events.

An example is the capability for the application server to assign a criticality level to a failed login attempt error message, a security-related error message being of a higher criticality.'
  desc 'check', "1. Access EM 
2. Expand the domain from the navigation tree, and select the AdminServer
3. Use the dropdown to select 'WebLogic Server' -> 'Logs' -> 'Log Configuration'
4. Select the 'Log Levels' tab, and within the table, expand 'Root Logger' node
5. Log levels for system-related events can be set here
6. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
7. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
8. Log levels for security-related events can be set here

If security-related events are not set properly, this is a finding."
  desc 'fix', "1. Access EM 
2. Expand the domain from the navigation tree, and select the AdminServer
3. Use the dropdown to select 'WebLogic Server' -> 'Logs' -> 'Log Configuration'
4. Select the 'Log Levels' tab, and within the table, expand 'Root Logger' node
5. Log levels for system-related events can be set here
6. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
7. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
8. Log levels for security-related events can be set here"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39212r628755_chk'
  tag severity: 'low'
  tag gid: 'V-235993'
  tag rid: 'SV-235993r628757_rule'
  tag stig_id: 'WBLC-09-000252'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag fix_id: 'F-39175r628756_fix'
  tag 'documentable'
  tag legacy: ['SV-70605', 'V-56351']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end

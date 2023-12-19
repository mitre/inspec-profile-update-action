control 'SV-235931' do
  title 'Oracle WebLogic must ensure remote sessions for accessing security functions and security-relevant information are audited.'
  desc 'Auditing must be utilized in order to track system activity, assist in diagnosing system issues and provide evidence needed for forensic investigations post security incident. 

Remote access by administrators requires that the admin activity be audited. 

Application servers provide a web- and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, ensure that the value 'Custom' is set in the 'Audit Level' dropdown
5. Beneath 'Audit Policy Settings' section, ensure that every checkbox is selected under the 'Select For Audit' column of the policy category table

If all auditable events for the 'Oracle Platform Security Services' audit component are not selected, then this is a finding."
  desc 'fix', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, select 'Custom' from the 'Audit Level' dropdown
5. Once it is enabled, click the 'Audit All Events' button and ensure every checkbox is selected under the 'Select For Audit' column of the policy category table. Click 'Apply'"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39150r628569_chk'
  tag severity: 'medium'
  tag gid: 'V-235931'
  tag rid: 'SV-235931r628571_rule'
  tag stig_id: 'WBLC-01-000013'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-39113r628570_fix'
  tag 'documentable'
  tag legacy: ['SV-70465', 'V-56211']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

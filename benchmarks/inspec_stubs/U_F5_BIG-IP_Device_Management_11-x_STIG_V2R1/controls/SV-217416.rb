control 'SV-217416' do
  title 'The BIG-IP appliance must be configured to audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Verify the BIG-IP appliance is configured to audit the enforcement actions used to restrict access associated with changes to the device.

Navigate to the BIG-IP System manager >> Logs >> Configuration >> Options.

Review configuration in the "Audit Logging" section.

Verify that "MCP" is set to Debug.

If the BIG-IP appliance is not configured to audit the enforcement actions used to restrict access associated with changes to the device, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to audit the enforcement actions used to restrict access associated with changes to the device.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18641r290802_chk'
  tag severity: 'medium'
  tag gid: 'V-217416'
  tag rid: 'SV-217416r557520_rule'
  tag stig_id: 'F5BI-DM-000215'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-18639r290803_fix'
  tag 'documentable'
  tag legacy: ['V-60211', 'SV-74641']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

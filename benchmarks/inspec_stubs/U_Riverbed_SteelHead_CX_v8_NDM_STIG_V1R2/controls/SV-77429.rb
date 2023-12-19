control 'SV-77429' do
  title 'Riverbed Optimization System (RiOS) must generate a log event for the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.

For RiOS, all configuration changes authorized or unauthorized are logged in the system logs. Log entries include the user that initiated the configuration change for accountability.'
  desc 'check', 'Verify that RiOS is configured to audit the enforcement actions used to restrict access associated with changes to the device.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging

Verify that "Minimum Severity" is set to "info"

If the minimum severity is not set to "info", this is a finding.'
  desc 'fix', 'Configure RiOS to audit the enforcement actions used to restrict access associated with changes to the device.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging

Set "Minimum Severity" to "info"
Click "Apply"
Navigate to the top of the screen and click "Save"'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62939'
  tag rid: 'SV-77429r1_rule'
  tag stig_id: 'RICX-DM-000085'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-68857r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

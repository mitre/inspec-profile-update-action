control 'SV-204797' do
  title 'The application server must log the enforcement actions used to restrict access associated with changes to the application server.'
  desc 'Without logging the enforcement of access restrictions against changes to the application server configuration, it will be difficult to identify attempted attacks, and a log trail will not be available for forensic investigation for after-the-fact actions.  Configuration changes may occur to any of the modules within the application server through the management interface, but logging of actions to the configuration of a module outside the application server is not logged.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Log items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Check the application server documentation and logs to determine if enforcement actions used to restrict access associated with changes to the application server are logged.

If these actions are not logged, this is a finding.'
  desc 'fix', 'Configure the application server to log the enforcement actions used to restrict access associated with changes to the application server.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4917r283038_chk'
  tag severity: 'medium'
  tag gid: 'V-204797'
  tag rid: 'SV-204797r879754_rule'
  tag stig_id: 'SRG-APP-000381-AS-000089'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-4917r283039_fix'
  tag 'documentable'
  tag legacy: ['V-57493', 'SV-71769']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

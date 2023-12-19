control 'SV-204742' do
  title 'The application server must be capable of reverting to the last known good configuration in the event of failed installations and upgrades.'
  desc 'Any changes to the components of the application server can have significant effects on the overall security of the system.

In order to ensure a prompt response to failed application installations and application server upgrades, the application server must provide an automated rollback capability that allows the system to be restored to a previous known good configuration state prior to the application installation or application server upgrade.'
  desc 'check', 'Check the application server documentation and configuration to determine if the application server provides an automated rollback capability to a known good configuration in the event of a failed installation and upgrade.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to automatically rollback to a known good configuration in the event of failed application installations and application server upgrades.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4862r282873_chk'
  tag severity: 'medium'
  tag gid: 'V-204742'
  tag rid: 'SV-204742r810851_rule'
  tag stig_id: 'SRG-APP-000133-AS-000093'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-4862r282874_fix'
  tag 'documentable'
  tag legacy: ['V-57497', 'SV-71773']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

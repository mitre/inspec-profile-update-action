control 'SV-204829' do
  title 'The application server must generate log records when concurrent logons from different workstations occur to the application server management interface.'
  desc "Being able to work on a system through multiple views into the application allows a user to work more efficiently and more accurately.  Before environments with windowing capabilities or multiple desktops, a user would log onto the application from different workstations or terminals.  With today's workstations, this is no longer necessary and may signal a compromised session or user account.

When concurrent logons are made from different workstations to the management interface, a log record needs to be generated.  This allows the system administrator to investigate the incident and to be aware of the incident."
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records showing concurrent logons from different workstations to the management interface.

If concurrent logons from different workstations are not logged, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records showing concurrent logons from different workstations to the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4949r283128_chk'
  tag severity: 'medium'
  tag gid: 'V-204829'
  tag rid: 'SV-204829r508029_rule'
  tag stig_id: 'SRG-APP-000506-AS-000231'
  tag gtitle: 'SRG-APP-000506'
  tag fix_id: 'F-4949r283129_fix'
  tag 'documentable'
  tag legacy: ['SV-71759', 'V-57483']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

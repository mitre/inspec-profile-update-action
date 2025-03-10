control 'SV-204828' do
  title 'The application must generate log records showing starting and ending times for user access to the application server management interface.'
  desc 'Determining when a user has accessed the management interface is important to determine the timeline of events when a security incident occurs.  Generating these events, especially if the management interface is accessed via a stateless protocol like HTTP, the log events will be generated when the user performs a logon (start) and when the user performs a logoff (end).  Without these events, the user and later investigators cannot determine the sequence of events and therefore cannot determine what may have happened and by whom it may have been done.

The generation of start and end times within log events allow the user to perform their due diligence in the event of a security breach.'
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records showing starting and ending times for user access to the management interface.

If log records are not generated showing starting and ending times of user access to the management interface, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records showing starting and ending times of user access to the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4948r283125_chk'
  tag severity: 'medium'
  tag gid: 'V-204828'
  tag rid: 'SV-204828r879876_rule'
  tag stig_id: 'SRG-APP-000505-AS-000230'
  tag gtitle: 'SRG-APP-000505'
  tag fix_id: 'F-4948r283126_fix'
  tag 'documentable'
  tag legacy: ['SV-71757', 'V-57481']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

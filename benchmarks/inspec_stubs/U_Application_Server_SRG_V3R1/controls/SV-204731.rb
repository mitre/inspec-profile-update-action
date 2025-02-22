control 'SV-204731' do
  title 'The application server must use internal system clocks to generate time stamps for log records.'
  desc 'Without the use of an approved and synchronized time source configured on the systems, events cannot be accurately correlated and analyzed to determine what is transpiring within the application server.

If an event has been triggered on the network, and the application server is not configured with the correct time, the event may be seen as insignificant, when in reality the events are related and may have a larger impact across the network. Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. Determining the correct time a particular event occurred on a system, via time stamps, is critical when conducting forensic analysis and investigating system events. 

Application servers must utilize the internal system clock when generating time stamps and log records.'
  desc 'check', 'Review the application server configuration files to determine if the internal system clock is used for time stamps. If this is not feasible, an alternative workaround is to take an action that generates an entry in the logs and then immediately query the operating system for the current time. A reasonable match between the two times will suffice as evidence that the system is using the internal clock for timestamps.

If the application server does not use the internal system clock to generate time stamps, this is a finding.'
  desc 'fix', 'Configure the application server to use internal system clocks to generate time stamps for log records.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4851r282840_chk'
  tag severity: 'medium'
  tag gid: 'V-204731'
  tag rid: 'SV-204731r508029_rule'
  tag stig_id: 'SRG-APP-000116-AS-000076'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-4851r282841_fix'
  tag 'documentable'
  tag legacy: ['V-35203', 'SV-46490']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end

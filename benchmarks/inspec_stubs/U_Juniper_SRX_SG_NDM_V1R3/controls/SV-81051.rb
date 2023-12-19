control 'SV-81051' do
  title 'The Juniper SRX Services Gateway must generate log records when changes are made to administrator privileges.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device logs change-log events of severity info or any to an external syslog server.

[edit]
show system syslog

host <syslog server address> {
  any <info | any>;
  source-address <device address>;
}

-OR-

host <syslog server address> {
  change-log <info | any>;
  source-address <device address>;
}

If an external syslog host is not configured to log facility change-log severity <info | any>, or configured for facility any severity <info | any>, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host is configured to log facility change-log or any, and severity info or any. 

[edit system syslog]
set host <syslog server address> any <info | any> 

 -OR-

[edit]
set host <syslog server address> change-log <info | any>'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67207r1_chk'
  tag severity: 'low'
  tag gid: 'V-66561'
  tag rid: 'SV-81051r1_rule'
  tag stig_id: 'JUSX-DM-000041'
  tag gtitle: 'SRG-APP-000495-NDM-000318'
  tag fix_id: 'F-72637r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

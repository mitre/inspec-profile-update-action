control 'SV-223196' do
  title 'The Juniper SRX Services Gateway must generate log records when concurrent logons from different workstations occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device generates a log when login events occur.

[edit]
show system syslog

host <syslog server address> {
  any any;
  source-address <device address>;
}

If an external syslog host is not configured to log, or configured for facility any severity any, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host to log facility any and severity info or any. There are multiple ways to accomplish this, the following is an example.

[edit system syslog]
set host <syslog server address> any any'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24869r513278_chk'
  tag severity: 'low'
  tag gid: 'V-223196'
  tag rid: 'SV-223196r513280_rule'
  tag stig_id: 'JUSX-DM-000046'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-24857r513279_fix'
  tag 'documentable'
  tag legacy: ['SV-81059', 'V-66569']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

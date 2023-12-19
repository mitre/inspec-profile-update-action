control 'SV-223194' do
  title 'The Juniper SRX Services Gateway must generate log records when logon events occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify the device generates a log when login events occur.

[edit]
show system syslog

host <syslog server address> {
  any <info | any>;
  source-address <device address>;
}

If an external syslog host is not configured to log, or configured for facility any severity <info | any>, this is a finding.'
  desc 'fix', 'Configure at least one external syslog host to log facility any and severity info or any. 

[edit system syslog]
set host <syslog server address> any <info | any>'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24867r513272_chk'
  tag severity: 'low'
  tag gid: 'V-223194'
  tag rid: 'SV-223194r513274_rule'
  tag stig_id: 'JUSX-DM-000043'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-24855r513273_fix'
  tag 'documentable'
  tag legacy: ['SV-81055', 'V-66565']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

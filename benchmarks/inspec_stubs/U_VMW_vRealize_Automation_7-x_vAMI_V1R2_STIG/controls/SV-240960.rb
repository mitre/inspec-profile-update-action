control 'SV-240960' do
  title 'The vAMI must enable logging.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. Privileged activities would occur through the management interface. This interface can be web-based or can be command line utilities. Whichever method is used by the application server, these activities must be logged.'
  desc 'check', 'At the command prompt, execute the following command:

grep traceLevel /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "traceLevel" is not "1", this is a finding.'
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'traceLevel: 1'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44193r676045_chk'
  tag severity: 'medium'
  tag gid: 'V-240960'
  tag rid: 'SV-240960r879875_rule'
  tag stig_id: 'VRAU-VA-000615'
  tag gtitle: 'SRG-APP-000504-AS-000229'
  tag fix_id: 'F-44152r676046_fix'
  tag 'documentable'
  tag legacy: ['SV-100915', 'V-90265']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

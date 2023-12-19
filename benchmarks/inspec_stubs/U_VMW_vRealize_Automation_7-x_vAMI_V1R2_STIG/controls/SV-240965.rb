control 'SV-240965' do
  title 'The vAMI must utilize syslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Protecting log data is important during a forensic investigation to ensure investigators can track and understand what may have occurred. Off-loading should be set up as a scheduled task but can be configured to be run manually, if other processes during the off-loading are manual. Off-loading is a common process in information systems with limited log storage capacity.'
  desc 'check', %q(At the command prompt, execute the following command:

grep traceFile /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "traceFile" is not "syslog', this is a finding.)
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg,

Configure the sfcb.cfg file with the following value: 'traceFile: syslog'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44198r676060_chk'
  tag severity: 'medium'
  tag gid: 'V-240965'
  tag rid: 'SV-240965r879886_rule'
  tag stig_id: 'VRAU-VA-000645'
  tag gtitle: 'SRG-APP-000515-AS-000203'
  tag fix_id: 'F-44157r676061_fix'
  tag 'documentable'
  tag legacy: ['SV-100925', 'V-90275']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

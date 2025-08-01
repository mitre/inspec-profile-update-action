control 'SV-100895' do
  title 'The vAMI must utilize syslog.'
  desc 'A clustered application server is made up of several servers working together to provide the user a failover and increased computing capability. To facilitate uniform logging in the event of an incident and later forensic investigation, the record format and logable events need to be uniform. This can be managed best from a centralized server. Without the ability to centrally manage the content captured in the log records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.'
  desc 'check', %q(At the command prompt, execute the following command:

grep traceFile /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "traceFile" is not "syslog', this is a finding.)
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'traceFile: syslog'"
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90245'
  tag rid: 'SV-100895r1_rule'
  tag stig_id: 'VRAU-VA-000415'
  tag gtitle: 'SRG-APP-000356-AS-000202'
  tag fix_id: 'F-96987r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end

control 'SV-239128' do
  title 'The Photon operating system must configure auditd to keep five rotated log files.'
  desc 'Audit logs are most useful when accessible by date, rather than size. This can be accomplished through a combination of an audit log rotation cron job, setting a reasonable number of logs to keep and configuring auditd to not rotate the logs on its own. This ensures that audit logs are accessible to the ISSO in the event of a central log processing failure.'
  desc 'check', 'At the command line, execute the following command:

# grep "^num_logs" /etc/audit/auditd.conf

Expected result:

num_logs = 5

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/audit/auditd.conf with a text editor. Add or change the "num_logs" line as follows:

num_logs = 5

At the command line, execute the following command:

# service auditd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42339r675190_chk'
  tag severity: 'medium'
  tag gid: 'V-239128'
  tag rid: 'SV-239128r856046_rule'
  tag stig_id: 'PHTN-67-000057'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-42298r675191_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end

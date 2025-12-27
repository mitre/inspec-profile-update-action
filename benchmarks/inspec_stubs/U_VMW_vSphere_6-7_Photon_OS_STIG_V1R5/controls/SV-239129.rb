control 'SV-239129' do
  title 'The Photon operating system must configure auditd to keep five rotated log files.'
  desc 'Audit logs are most useful when accessible by date, rather than size. This can be accomplished through a combination of an audit log rotation cron job, setting a reasonable number of logs to keep and configuring auditd to not rotate the logs on its own. This ensures that audit logs are accessible to the ISSO in the event of a central log processing failure.'
  desc 'check', 'At the command line, execute the following command:

# grep "^max_log_file_action" /etc/audit/auditd.conf

Expected result:

max_log_file_action = IGNORE

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/audit/auditd.conf with a text editor. 

Add or change the "max_log_file_action" line as follows:

max_log_file_action = IGNORE

At the command line, execute the following command:

# service auditd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42340r675193_chk'
  tag severity: 'medium'
  tag gid: 'V-239129'
  tag rid: 'SV-239129r856047_rule'
  tag stig_id: 'PHTN-67-000058'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-42299r675194_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end

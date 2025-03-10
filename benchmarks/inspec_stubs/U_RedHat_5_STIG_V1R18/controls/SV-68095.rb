control 'SV-68095' do
  title 'The audit system must alert the SA in the event of an audit processing failure.'
  desc "An accurate and current audit trail is essential for maintaining a record of system activity.  If the system fails, the SA must be notified and must take prompt action to correct the problem.

Minimally, the system must log this event, and the SA will receive this notification during the daily system log review.  If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site's established operations management systems and procedures."
  desc 'check', 'Verify the /etc/audit/auditd.conf has the disk_full_action and disk_error_action parameters set.

Procedure:
# grep disk_full_action /etc/audit/auditd.conf

If the disk_full_action parameter is missing or set to "suspend" or "ignore" this is a finding.

# grep disk_error_action /etc/audit/auditd.conf

If the disk_error_action parameter is missing or set to "suspend" or "ignore" this is a finding.'
  desc 'fix', 'Edit /etc/audit/auditd.conf and set the disk_full_action and/or disk_error_action parameters to a valid setting of "syslog", "exec", "single" or "halt", adding the parameters if necessary.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-54715r1_chk'
  tag severity: 'low'
  tag gid: 'V-22374'
  tag rid: 'SV-68095r2_rule'
  tag stig_id: 'GEN002719'
  tag gtitle: 'GEN002719'
  tag fix_id: 'F-32421r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

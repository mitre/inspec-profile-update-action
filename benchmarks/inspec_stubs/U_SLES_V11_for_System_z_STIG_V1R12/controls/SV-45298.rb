control 'SV-45298' do
  title 'The audit system must alert the SA when the audit storage volume approaches its capacity.'
  desc 'An accurate and current audit trail is essential for maintaining a record of system activity.  If the system fails, the SA must be notified and must take prompt action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the daily system log review.  If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site’s established operations management systems and procedures.'
  desc 'check', %q(Check /etc/audit/auditd.conf for the space_left_action and action_mail_acct parameters.
# egrep 'space_left_action|action_mail_acct' /etc/audit/auditd.conf
 If the space_left_action or the action_mail_acct parameters are set to blanks, this is a finding.

If the space_left_action is set to "syslog" the system logs the event, this is not a finding.

If the space_left_action is set to "exec" the system executes a designated script. If this script informs the SA of the event, this is not a finding.

If the space_left_action parameter is missing, this is a finding.
If the space_left_action parameter is set to "ignore" or "suspend" no logging would be performed after the event, this is a finding.
If the space_left_action parameter is set to "single" or "halt" this effectively stops the system causing a Denial of Service, this is a finding.

If the space_left_action is set to "email" and the action_mail_acct parameter is not set to the e-mail address of the system administrator, this is a finding. The action_mail_acct parameter, if missing, defaults to "root". Note that if the email address of the system administrator is on a remote system "sendmail" must be available.)
  desc 'fix', 'Edit /etc/audit/auditd.conf and set the space_left_action parameter to a valid setting other than "ignore". If the space_left_action parameter is set to "email" set the action_mail_acct parameter to an e-mail address for the system administrator.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42646r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22375'
  tag rid: 'SV-45298r1_rule'
  tag stig_id: 'GEN002730'
  tag gtitle: 'GEN002730'
  tag fix_id: 'F-38694r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000143']
  tag nist: ['AU-5 (1)']
end

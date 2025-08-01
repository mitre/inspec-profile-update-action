control 'SV-26518' do
  title 'The audit system must alert the SA when the audit storage volume approaches its capacity.'
  desc "An accurate and current audit trail is essential for maintaining a record of system activity.  If the system fails, the SA must be notified and must take prompt action to correct the problem.

Minimally, the system must log this event, and the SA will receive this notification during the daily system log review.  If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site's established operations management systems and procedures."
  desc 'fix', 'Edit /etc/audit/auditd.conf and set the space_left_action parameter to a valid setting other than "ignore". If the space_left_action parameter is set to "email" set the action_mail_acct parameter to an e-mail address for the system administrator.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22375'
  tag rid: 'SV-26518r2_rule'
  tag stig_id: 'GEN002730'
  tag gtitle: 'GEN002730'
  tag fix_id: 'F-32424r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000143']
  tag nist: ['AU-5 (1)']
end

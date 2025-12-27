control 'SV-218057' do
  title 'The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.'
  desc 'Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.'
  desc 'check', 'Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator: 

action_mail_acct = root


If auditd is not configured to send emails per identified actions, this is a finding.'
  desc 'fix', 'The "auditd" service can be configured to send email to a designated account in certain situations. Add or correct the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations: 

action_mail_acct = root'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19538r377186_chk'
  tag severity: 'medium'
  tag gid: 'V-218057'
  tag rid: 'SV-218057r603264_rule'
  tag stig_id: 'RHEL-06-000313'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-19536r377187_fix'
  tag 'documentable'
  tag legacy: ['SV-50481', 'V-38680']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

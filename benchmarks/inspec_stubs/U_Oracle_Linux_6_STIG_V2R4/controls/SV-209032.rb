control 'SV-209032' do
  title 'The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.'
  desc 'Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.'
  desc 'check', 'Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator: 

action_mail_acct = root

If auditd is not configured to send emails per identified actions, this is a finding.'
  desc 'fix', 'The "auditd" service can be configured to send email to a designated account in certain situations. Add or correct the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations: 

action_mail_acct = root'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9285r357881_chk'
  tag severity: 'medium'
  tag gid: 'V-209032'
  tag rid: 'SV-209032r603263_rule'
  tag stig_id: 'OL6-00-000313'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-9285r357882_fix'
  tag 'documentable'
  tag legacy: ['V-51057', 'SV-65263']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

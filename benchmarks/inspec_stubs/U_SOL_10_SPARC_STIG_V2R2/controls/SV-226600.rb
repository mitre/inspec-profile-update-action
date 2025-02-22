control 'SV-226600' do
  title 'The audit system must alert the SA when the audit storage volume approaches its capacity.'
  desc "An accurate and current audit trail is essential for maintaining a record of system activity.  If the system fails, the SA must be notified and must take prompt action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the daily system log review.  If feasible, active alerting (such as email or paging) should be employed consistent with the site's established operations management systems and procedures."
  desc 'check', "Verify the presence of an audit_warn entry in /etc/mail/aliases.

# grep audit_warn /etc/mail/aliases

If there is no audit_warn entry in /etc/mail/aliases, this is a finding.

Verify the minfree parameter in /etc/security/audit_control.

# egrep '^minfree:' /etc/security/audit_control

If the minfree parameter is set to zero or not set at all, this is a finding."
  desc 'fix', 'If necessary, add an audit_warn alias to /etc/mail/aliases that will forward to designated system administrator(s).

# vi /etc/mail/aliases

Put the updated aliases file into service.

# newaliases

If necessary, add or update the minfree: parameter in /etc/security/audit_control.  

# vi /etc/security/audit_control

Ensure the minfree value is greater than zero and less than 100.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36397r602794_chk'
  tag severity: 'medium'
  tag gid: 'V-226600'
  tag rid: 'SV-226600r603265_rule'
  tag stig_id: 'GEN002730'
  tag gtitle: 'SRG-OS-000343'
  tag fix_id: 'F-36361r602795_fix'
  tag 'documentable'
  tag legacy: ['V-22375', 'SV-40564']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end

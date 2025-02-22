control 'SV-226598' do
  title 'The audit system must alert the SA in the event of an audit processing failure.'
  desc "An accurate and current audit trail is essential for maintaining 
a record of system activity. If the system fails, the SA must be notified and must take prompt 
action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the 
daily system log review. If feasible, active alerting (such as email or paging) should be 
employed consistent with the site's established operations management systems and procedures."
  desc 'check', 'Verify the presence of an audit_warn entry in /etc/mail/aliases.

# grep audit_warn /etc/mail/aliases

If there is no audit_warn entry in /etc/mail/aliases, this is a finding.'
  desc 'fix', 'Add an audit_warn alias to /etc/mail/aliases that will forward to designated system administrator(s).

# vi /etc/mail/aliases

Put the updated aliases file into service.

# newaliases'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36396r602791_chk'
  tag severity: 'low'
  tag gid: 'V-226598'
  tag rid: 'SV-226598r603265_rule'
  tag stig_id: 'GEN002719'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-36360r602792_fix'
  tag 'documentable'
  tag legacy: ['V-22374', 'SV-40562']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

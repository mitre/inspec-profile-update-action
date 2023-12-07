control 'SV-40364' do
  title 'The /etc/syslog.conf file must be group-owned by bin, sys, or system.'
  desc 'If the group owner of /etc/syslog.conf is not root, bin, or sys, unauthorized users could be permitted to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf group ownership.

Procedure:
# ls -lL /etc/syslog.conf

If /etc/syslog.conf is not group-owned by sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/syslog.conf file to bin, sys, or system.

Procedure:
# chgrp system /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39246r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4394'
  tag rid: 'SV-40364r1_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'GEN005420'
  tag fix_id: 'F-34348r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

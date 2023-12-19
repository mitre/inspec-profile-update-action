control 'SV-37711' do
  title 'The /etc/syslog.conf file must be group-owned by root, bin, sys, or system.'
  desc 'If the group owner of /etc/syslog.conf is not root, bin, or sys, unauthorized users could be permitted to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf or /etc/rsyslog.conf group ownership.

Procedure:
# ls -lL /etc/syslog.conf
Or:
# ls -lL /etc/syslog.conf

If /etc/syslog.conf or /etc/rsyslog.conf is not group owned by root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Procedure:
# chgrp root /etc/syslog.conf   
Or
# chgrp root /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36910r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4394'
  tag rid: 'SV-37711r2_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'GEN005420'
  tag fix_id: 'F-32088r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

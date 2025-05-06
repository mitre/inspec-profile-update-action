control 'SV-4394' do
  title 'The /etc/syslog.conf file must be group-owned by root, bin, sys, or system.'
  desc 'If the group owner of /etc/syslog.conf is not root, bin, or sys, unauthorized users could be permitted to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf group ownership.

Procedure:
# ls -lL /etc/syslog.conf

If /etc/syslog.conf is not group-owned by root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/syslog.conf file to root, bin, sys, or system.

Procedure:
# chgrp root /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8273r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4394'
  tag rid: 'SV-4394r2_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'GEN005420'
  tag fix_id: 'F-4305r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

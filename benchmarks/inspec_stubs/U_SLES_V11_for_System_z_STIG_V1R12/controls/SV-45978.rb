control 'SV-45978' do
  title 'The /etc/rsyslog.conf file must be group-owned by root, bin, sys, or system.'
  desc 'If the group owner of /etc/syslog.conf is not root, bin, or sys, unauthorized users could be permitted to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/rsyslog.conf group ownership.

Procedure:
# ls -lL /etc/rsyslog*

If any rsyslog.conf file is not group owned by root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/rsyslog.conf file to root, bin, sys, or system.

Procedure:
# chgrp root <rsyslog configuration file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43260r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4394'
  tag rid: 'SV-45978r1_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'GEN005420'
  tag fix_id: 'F-39343r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

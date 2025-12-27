control 'SV-227888' do
  title 'The /etc/syslog.conf file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of /etc/syslog.conf is not root, bin, or sys, unauthorized users could be permitted to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf group ownership.

Procedure:
# ls -lL /etc/syslog.conf

If /etc/syslog.conf is not group-owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/syslog.conf file to root, bin, or sys.

Procedure:
# chgrp root /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30050r490060_chk'
  tag severity: 'medium'
  tag gid: 'V-227888'
  tag rid: 'SV-227888r603266_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30038r490061_fix'
  tag 'documentable'
  tag legacy: ['V-4394', 'SV-39892']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

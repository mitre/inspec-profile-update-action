control 'SV-218592' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20067r555974_chk'
  tag severity: 'medium'
  tag gid: 'V-218592'
  tag rid: 'SV-218592r603259_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20065r555975_fix'
  tag 'documentable'
  tag legacy: ['V-4394', 'SV-65303']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

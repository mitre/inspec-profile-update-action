control 'SV-39892' do
  title 'The /etc/syslog.conf file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of /etc/syslog.conf is not root, bin, or sys, unauthorized users could be permitted to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'fix', 'Change the group owner of the /etc/syslog.conf file to root, bin, or sys.

Procedure:
# chgrp root /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4394'
  tag rid: 'SV-39892r1_rule'
  tag stig_id: 'GEN005420'
  tag gtitle: 'GEN005420'
  tag fix_id: 'F-34049r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

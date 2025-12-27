control 'SV-227813' do
  title 'The inetd.conf file must be group-owned by root, bin, or sys.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the inetd.conf file.

Procedure:
# ls -alL /etc/inet/inetd.conf

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the inetd.conf file.
Procedure:
# chgrp sys /etc/inet/inetd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29975r489796_chk'
  tag severity: 'medium'
  tag gid: 'V-227813'
  tag rid: 'SV-227813r603266_rule'
  tag stig_id: 'GEN003730'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29963r489797_fix'
  tag 'documentable'
  tag legacy: ['V-22423', 'SV-39884']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-218500' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be group-owned by root, bin, sys, or system.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration possibly weakening the system's security posture."
  desc 'check', 'Check the group ownership of the xinetd configuration files and directories.

Procedure:
# ls -alL /etc/xinetd.conf /etc/xinetd.d

If a file or directory is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the xinetd configuration files and directories.

Procedure:
# chgrp -R root /etc/xinetd.conf /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19975r562633_chk'
  tag severity: 'medium'
  tag gid: 'V-218500'
  tag rid: 'SV-218500r603259_rule'
  tag stig_id: 'GEN003730'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19973r562634_fix'
  tag 'documentable'
  tag legacy: ['V-22423', 'SV-64235']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

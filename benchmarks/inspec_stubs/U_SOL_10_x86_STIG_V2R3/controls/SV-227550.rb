control 'SV-227550' do
  title 'The /etc/zones directory, and its contents, must be group-owned by root, sys, or bin.'
  desc 'Solaris zones configuration files must be protected against illicit creation, modification, and deletion.'
  desc 'check', 'Check the group ownership of the files and directories.

# ls -lLRa /etc/zones

If the group owner of the directory and all files is not root, sys, or bin, this is a finding.

If zones are not installed on the system, this is not a finding.'
  desc 'fix', 'Change the group ownership of the files and directories.
# chgrp -R sys /etc/zones
# chgrp root /etc/zones/*.xml
# chgrp bin /etc/zones/SUN*.xml'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29712r488183_chk'
  tag severity: 'medium'
  tag gid: 'V-227550'
  tag rid: 'SV-227550r603266_rule'
  tag stig_id: 'GEN000000-SOL00560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29700r488184_fix'
  tag 'documentable'
  tag legacy: ['V-22604', 'SV-27018']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

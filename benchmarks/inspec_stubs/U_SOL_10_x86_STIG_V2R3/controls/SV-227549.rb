control 'SV-227549' do
  title 'The /etc/zones directory, and its contents, must be owned by root.'
  desc 'Solaris zones configuration files must be protected against illicit creation, modification, and deletion.'
  desc 'check', 'Check the ownership of the files and directories.

# ls -lLdR /etc/zones

If the owner of the file is not root, this is a finding.
If zones are not installed on the system, this is not a finding.'
  desc 'fix', 'Change the ownership of the files and directories.
# chown -R root /etc/zones'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29711r488180_chk'
  tag severity: 'medium'
  tag gid: 'V-227549'
  tag rid: 'SV-227549r603266_rule'
  tag stig_id: 'GEN000000-SOL00540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29699r488181_fix'
  tag 'documentable'
  tag legacy: ['V-22603', 'SV-27016']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

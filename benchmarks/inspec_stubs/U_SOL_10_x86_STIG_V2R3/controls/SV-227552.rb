control 'SV-227552' do
  title 'The /etc/zones directory, and its contents, must not have an extended ACL.'
  desc 'Solaris zones configuration files must be protected against illicit creation, modification, and deletion.'
  desc 'check', 'Check the permissions of the file.
# ls -lLd /etc/zones
# ls -lLR /etc/zones
If the permissions of the file or directory contains a "+", an extended ACL is present, this is a finding.

If zones are not installed on the system, this is not a finding.'
  desc 'fix', 'Remove  the extended ACL from the file.
# chmod A- <file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29714r488189_chk'
  tag severity: 'medium'
  tag gid: 'V-227552'
  tag rid: 'SV-227552r603266_rule'
  tag stig_id: 'GEN000000-SOL00600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29702r488190_fix'
  tag 'documentable'
  tag legacy: ['V-22606', 'SV-27020']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

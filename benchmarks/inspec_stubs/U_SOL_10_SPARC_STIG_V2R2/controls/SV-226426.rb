control 'SV-226426' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28587r482639_chk'
  tag severity: 'medium'
  tag gid: 'V-226426'
  tag rid: 'SV-226426r603265_rule'
  tag stig_id: 'GEN000000-SOL00600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28575r482640_fix'
  tag 'documentable'
  tag legacy: ['SV-27020', 'V-22606']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

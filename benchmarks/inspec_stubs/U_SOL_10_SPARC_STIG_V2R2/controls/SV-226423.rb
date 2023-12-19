control 'SV-226423' do
  title 'The /etc/zones directory, and its contents, must be owned by root.'
  desc 'Solaris zones configuration files must be protected against illicit creation, modification, and deletion.'
  desc 'check', 'Check the ownership of the files and directories.

# ls -lLdR /etc/zones

If the owner of the file is not root, this is a finding.
If zones are not installed on the system, this is not a finding.'
  desc 'fix', 'Change the ownership of the files and directories.
# chown -R root /etc/zones'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28584r482630_chk'
  tag severity: 'medium'
  tag gid: 'V-226423'
  tag rid: 'SV-226423r603265_rule'
  tag stig_id: 'GEN000000-SOL00540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28572r482631_fix'
  tag 'documentable'
  tag legacy: ['SV-27016', 'V-22603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

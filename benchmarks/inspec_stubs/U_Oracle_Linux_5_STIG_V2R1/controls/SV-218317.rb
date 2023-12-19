control 'SV-218317' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', "Verify run control scripts have no extended ACLs.
# ls -lL /etc/rc* /etc/init.d
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <run control script with extended ACL>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19792r561707_chk'
  tag severity: 'medium'
  tag gid: 'V-218317'
  tag rid: 'SV-218317r603259_rule'
  tag stig_id: 'GEN001590'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19790r561708_fix'
  tag 'documentable'
  tag legacy: ['V-22353', 'SV-63847']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

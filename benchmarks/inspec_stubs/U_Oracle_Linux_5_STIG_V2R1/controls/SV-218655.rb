control 'SV-218655' do
  title 'The /etc/news/hosts.nntp.nolimit file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', %q(Check the permissions for "/etc/news/hosts.nntp.nolimit".

# ls -lL /etc/news/hosts.nntp.nolimit
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/hosts.nntp.nolimit'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20130r562900_chk'
  tag severity: 'medium'
  tag gid: 'V-218655'
  tag rid: 'SV-218655r603259_rule'
  tag stig_id: 'GEN006290'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20128r562901_fix'
  tag 'documentable'
  tag legacy: ['V-22503', 'SV-63915']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

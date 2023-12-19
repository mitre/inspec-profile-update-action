control 'SV-218653' do
  title 'The /etc/news/incoming.conf file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the "incoming.conf" file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/news/incoming.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/incoming.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20128r562897_chk'
  tag severity: 'medium'
  tag gid: 'V-218653'
  tag rid: 'SV-218653r603259_rule'
  tag stig_id: 'GEN006270'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20126r562898_fix'
  tag 'documentable'
  tag legacy: ['V-22502', 'SV-63925']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

control 'SV-46120' do
  title 'The Network File System (NFS) exports configuration file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', "Check the permissions of the NFS export configuration file.
# ls -lL /etc/exports
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/exports'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43377r1_chk'
  tag severity: 'low'
  tag gid: 'V-22493'
  tag rid: 'SV-46120r1_rule'
  tag stig_id: 'GEN005770'
  tag gtitle: 'GEN005770'
  tag fix_id: 'F-39461r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

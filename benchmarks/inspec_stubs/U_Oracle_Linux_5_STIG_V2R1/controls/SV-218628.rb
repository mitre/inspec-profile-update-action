control 'SV-218628' do
  title 'The Network File System (NFS) exports configuration file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', "Check the permissions of the NFS export configuration file.
# ls -lL /etc/exports
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/exports'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20103r562864_chk'
  tag severity: 'low'
  tag gid: 'V-218628'
  tag rid: 'SV-218628r603259_rule'
  tag stig_id: 'GEN005770'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20101r562865_fix'
  tag 'documentable'
  tag legacy: ['V-22493', 'SV-64191']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end

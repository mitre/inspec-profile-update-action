control 'SV-38823' do
  title 'The NFS exports configuration file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', '# aclget /etc/exports
If the extended attributes are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the NFS export configuration file and change extended attributes to disabled.

#acledit /etc/exports'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37070r1_chk'
  tag severity: 'low'
  tag gid: 'V-22493'
  tag rid: 'SV-38823r1_rule'
  tag stig_id: 'GEN005770'
  tag gtitle: 'GEN005770'
  tag fix_id: 'F-32337r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

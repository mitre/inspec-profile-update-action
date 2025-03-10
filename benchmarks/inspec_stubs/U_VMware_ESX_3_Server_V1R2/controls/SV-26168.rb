control 'SV-26168' do
  title 'The NFS exports configuration file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial-of-Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', 'Determine if the NFS exports configuration file has an extended ACL.  If it does, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the NFS export configuration file.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29275r1_chk'
  tag severity: 'low'
  tag gid: 'V-22493'
  tag rid: 'SV-26168r1_rule'
  tag stig_id: 'GEN005770'
  tag gtitle: 'GEN005770'
  tag fix_id: 'F-26302r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

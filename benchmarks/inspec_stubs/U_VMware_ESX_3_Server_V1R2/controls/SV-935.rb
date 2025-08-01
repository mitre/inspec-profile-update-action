control 'SV-935' do
  title 'The NFS server must not allow remote root access.'
  desc 'If the NFS server allows root access to local file systems from remote hosts, this access could be used to compromise the system.'
  desc 'check', 'Determine if the NFS server is exporting with the root access option.

Procedure:
# exportfs -v | grep "root="

If an export with the root option is found, this is a finding.'
  desc 'fix', 'Edit /etc/exports and remove the root= option for all exports.  Re-export the file systems.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-867r2_chk'
  tag severity: 'medium'
  tag gid: 'V-935'
  tag rid: 'SV-935r2_rule'
  tag stig_id: 'GEN005880'
  tag gtitle: 'GEN005880'
  tag fix_id: 'F-1089r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'EBRP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

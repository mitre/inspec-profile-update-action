control 'SV-928' do
  title 'The NFS export configuration file must be owned by root.'
  desc "Failure to give ownership of the NFS export configuration file to root provides the designated owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of the NFS export configuration file.  If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the NFS export configuration file to root.
# chown root <NFS export file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-855r2_chk'
  tag severity: 'medium'
  tag gid: 'V-928'
  tag rid: 'SV-928r2_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'GEN005740'
  tag fix_id: 'F-1082r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-28444' do
  title 'The NFS export configuration file must be owned by root.'
  desc "Failure to give ownership of the NFS export configuration file to root provides the designated owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the owner of the dfstab file to root.

Example:
# chown root /etc/dfs/dfstab'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-928'
  tag rid: 'SV-28444r1_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'GEN005740'
  tag fix_id: 'F-25755r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

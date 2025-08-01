control 'SV-227006' do
  title 'The NFS export configuration file must be owned by root.'
  desc "Failure to give ownership of the NFS export configuration file to root provides the designated owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of the dfstab file.

Example:
# ls -lL /etc/dfs/dfstab 

If the export configuration file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the dfstab file to root.

Example:
# chown root /etc/dfs/dfstab'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29168r485363_chk'
  tag severity: 'medium'
  tag gid: 'V-227006'
  tag rid: 'SV-227006r603265_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29156r485364_fix'
  tag 'documentable'
  tag legacy: ['V-928', 'SV-28444']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-35180' do
  title 'The NFS export configuration file must be owned by root.'
  desc "Failure to give ownership of the NFS export configuration file to root provides the designated owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', %q(Check the owner of the /etc/dfs/dfstab file.
# echo `ls -lL /etc/dfs/dfstab` | sed -e 's/^[  \t]*//' |  tr '\011' ' ' | tr -s  ' ' | cut -f 3,3 -d " "

If the /etc/dfs/dfstab configuration file is not owned by root or bin, this is a finding.)
  desc 'fix', 'Change the owner of the /etc/dfs/dfstab file to root.
# chown root /etc/dfs/dfstab'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-37986r2_chk'
  tag severity: 'medium'
  tag gid: 'V-928'
  tag rid: 'SV-35180r1_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'GEN005740'
  tag fix_id: 'F-33229r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

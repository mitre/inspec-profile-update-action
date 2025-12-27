control 'SV-38998' do
  title 'The NFS export configuration file must be owned by root.'
  desc "Failure to give ownership of the NFS export configuration file to root provides the designated owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', %q(# echo `ls -lL /etc/exports` | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | cut -f 3,3 -d " " 

If the export configuration file is not owned by root, this is a finding.)
  desc 'fix', 'Change the owner of the exports file to root.
	
Example:
# chown root /etc/exports'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35023r1_chk'
  tag severity: 'medium'
  tag gid: 'V-928'
  tag rid: 'SV-38998r1_rule'
  tag stig_id: 'GEN005740'
  tag gtitle: 'GEN005740'
  tag fix_id: 'F-30316r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

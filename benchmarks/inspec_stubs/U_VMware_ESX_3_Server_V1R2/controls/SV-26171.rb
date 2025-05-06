control 'SV-26171' do
  title 'All NFS-exported system files and system directories must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group ownership of sensitive files or directories to root provides the members of the owning group with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', 'Determine if the NFS exported directories on the system are group-owned by root.  If any are not, this is a finding.'
  desc 'fix', 'Change the group owner of NFS exported directories to root.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29278r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22496'
  tag rid: 'SV-26171r1_rule'
  tag stig_id: 'GEN005810'
  tag gtitle: 'GEN005810'
  tag fix_id: 'F-26305r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

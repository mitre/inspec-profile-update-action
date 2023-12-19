control 'SV-4091' do
  title 'System start-up files must only execute programs owned by a privileged UID or an application.'
  desc 'System start-up files that execute programs owned by other than root (or another privileged user) or an application indicates the system may have been compromised.'
  desc 'check', 'Check the ownership of any files executed from system startup scripts.  If any of these files are not owned by root, bin, sys, or other, this is a finding.'
  desc 'fix', 'Change the ownership of the file executed from system startup scripts to root, bin, sys, or other.
# chown root <executed file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28190r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4091'
  tag rid: 'SV-4091r2_rule'
  tag stig_id: 'GEN001700'
  tag gtitle: 'GEN001700'
  tag fix_id: 'F-24458r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-38422' do
  title 'System start-up files must only execute programs owned by a privileged UID or an application.'
  desc 'System start-up files that execute programs owned by other than root (or another privileged user) or an application indicate that the system may have been compromised.'
  desc 'check', %q(Determine the ownership of programs executed by system start-up files. 
# more `ls -alL /sbin/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "`

If any executed program is not owned by root, sys, bin, or in rare cases, an application account, this is a finding.)
  desc 'fix', 'Change the ownership of the file executed from system startup scripts to root, bin, sys, or the application account, where required.
# chown root <executed file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36374r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4091'
  tag rid: 'SV-38422r1_rule'
  tag stig_id: 'GEN001700'
  tag gtitle: 'GEN001700'
  tag fix_id: 'F-31712r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-26000' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, the startup files could be modified to insert malicious commands.'
  desc 'check', 'Verify run control scripts have no extended ACLs.
# ls -lL /etc/rc* /etc/init.d
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the run control script(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27524r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22353'
  tag rid: 'SV-26000r1_rule'
  tag stig_id: 'GEN001590'
  tag gtitle: 'GEN001590'
  tag fix_id: 'F-26196r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

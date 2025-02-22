control 'SV-226030' do
  title 'Users with administrative privilege must be documented.'
  desc 'Administrative accounts may perform any action on a system.  Users with administrative accounts must be documented to ensure those with this level of access are clearly identified.'
  desc 'check', 'Review the necessary documentation that identifies the members of the Administrators group.  If a list of all users belonging to the Administrators group is not maintained with the ISSO, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Administrators group.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27732r475413_chk'
  tag severity: 'medium'
  tag gid: 'V-226030'
  tag rid: 'SV-226030r794369_rule'
  tag stig_id: 'WN12-00-000004'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27720r475414_fix'
  tag 'documentable'
  tag legacy: ['SV-51575', 'V-36658']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

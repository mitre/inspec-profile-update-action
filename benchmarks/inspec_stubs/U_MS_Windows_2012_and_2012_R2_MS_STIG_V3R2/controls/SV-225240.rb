control 'SV-225240' do
  title 'Users with administrative privilege must be documented.'
  desc 'Administrative accounts may perform any action on a system.  Users with administrative accounts must be documented to ensure those with this level of access are clearly identified.'
  desc 'check', 'Review the necessary documentation that identifies the members of the Administrators group.  If a list of all users belonging to the Administrators group is not maintained with the ISSO, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Administrators group.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26939r471062_chk'
  tag severity: 'medium'
  tag gid: 'V-225240'
  tag rid: 'SV-225240r569185_rule'
  tag stig_id: 'WN12-00-000004'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26927r471063_fix'
  tag 'documentable'
  tag legacy: ['SV-51575', 'V-36658']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

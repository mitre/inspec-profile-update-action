control 'SV-48275' do
  title 'Users with Administrative privilege must be documented.'
  desc 'Administrative accounts may perform any action on a system.  Users with administrative accounts must be documented to ensure those with this level of access are clearly identified.'
  desc 'check', 'Review the necessary documentation that identifies the members of the Administrators group.  If a list of all users belonging to the Administrators group is not maintained with the ISSO, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Administrators group.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44953r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36658'
  tag rid: 'SV-48275r3_rule'
  tag stig_id: 'WN08-00-000005-01'
  tag gtitle: 'WIN00-000005-01'
  tag fix_id: 'F-41410r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

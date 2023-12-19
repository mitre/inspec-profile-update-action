control 'SV-45739' do
  title 'A separate file system must be used for user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /home path is a separate filesystem.
# grep "/home " /etc/fstab
If no result is returned, /home is not on a separate filesystem this is a finding.'
  desc 'fix', 'Migrate the /home (or equivalent) path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43102r1_chk'
  tag severity: 'low'
  tag gid: 'V-12003'
  tag rid: 'SV-45739r1_rule'
  tag stig_id: 'GEN003620'
  tag gtitle: 'GEN003620'
  tag fix_id: 'F-39140r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end

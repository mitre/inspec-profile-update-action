control 'SV-44954' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'check', "Perform the following to check NIS file premissions.
# ls -la /var/yp/*;
If the file's mode is more permissive than 0755, this is a finding."
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to 0755 or less permissive.

Procedure (example):
# chmod 0755 <filename>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42381r1_chk'
  tag severity: 'medium'
  tag gid: 'V-791'
  tag rid: 'SV-44954r1_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'GEN001360'
  tag fix_id: 'F-38379r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

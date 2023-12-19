control 'SV-37272' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'check', "Perform the following to check NIS file permissions.

# ls -la /var/yp/*

If the file's mode is more permissive than 0755, this is a finding."
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to 0755 or less permissive.

Procedure (example):
# chmod 0755 <filename>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35964r3_chk'
  tag severity: 'medium'
  tag gid: 'V-791'
  tag rid: 'SV-37272r1_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'GEN001360'
  tag fix_id: 'F-31220r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-27039' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require a valid root password before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', 'Ensure the root account for any bootable partitions has a password assigned in the /etc/security/passwd file.'
  desc 'fix', 'Assign a root account password for any bootable partition.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27960r1_chk'
  tag severity: 'medium'
  tag gid: 'V-756'
  tag rid: 'SV-27039r1_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'GEN000020'
  tag fix_id: 'F-24305r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

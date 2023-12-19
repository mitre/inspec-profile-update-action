control 'SV-45704' do
  title 'The kernel core dump data directory must be owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the ownership of the kernel core dump data directory.
# ls -ld /var/crash
If the kernel core dump data directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the kernel core dump data directory to root. 
# chown root /var/crash'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43069r1_chk'
  tag severity: 'low'
  tag gid: 'V-11997'
  tag rid: 'SV-45704r1_rule'
  tag stig_id: 'GEN003520'
  tag gtitle: 'GEN003520'
  tag fix_id: 'F-39102r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-226882' do
  title 'The kernel core dump data directory must be owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the ownership of the kernel core dump data directory.

# ls -ld /var/crash
OR
# ls -ld `grep DUMPADM_SAVDIR /etc/dumpadm.conf | cut -d= -f2`

If the kernel core dump data directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the kernel core dump data directory to root. 
# chown root /var/crash'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29044r484930_chk'
  tag severity: 'low'
  tag gid: 'V-226882'
  tag rid: 'SV-226882r603265_rule'
  tag stig_id: 'GEN003520'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29032r484931_fix'
  tag 'documentable'
  tag legacy: ['SV-27407', 'V-11997']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-12498' do
  title 'The kernel core dump data directory must be owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the ownership of the kernel core dump data directory.  If the kernel core dump data directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the kernel core dump data directory to root.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7962r2_chk'
  tag severity: 'low'
  tag gid: 'V-11997'
  tag rid: 'SV-12498r2_rule'
  tag stig_id: 'GEN003520'
  tag gtitle: 'GEN003520'
  tag fix_id: 'F-11258r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

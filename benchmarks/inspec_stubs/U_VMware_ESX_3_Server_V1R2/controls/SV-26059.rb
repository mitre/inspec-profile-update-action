control 'SV-26059' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in Denial-of-Service by exhausting the available space on the target file system. The kernel core dump process may increase the amount of time a system is unavailable due to a crash. Kernel core dumps can be useful for kernel debugging.'
  desc 'check', 'Determine if kernel core dumps are enabled on the system.  If so, this is a finding.'
  desc 'fix', 'Disable kernel core dumps on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29242r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22404'
  tag rid: 'SV-26059r1_rule'
  tag stig_id: 'GEN003510'
  tag gtitle: 'GEN003510'
  tag fix_id: 'F-26261r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

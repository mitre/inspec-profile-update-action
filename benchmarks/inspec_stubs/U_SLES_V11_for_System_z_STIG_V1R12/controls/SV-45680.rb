control 'SV-45680' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system. The kernel core dump process may increase the amount of time a system is unavailable due to a crash. Kernel core dumps can be useful for kernel debugging.'
  desc 'check', 'Check that the dumpconf service is not running.
# /etc/init.d/dumpconf status
If a status of “running" is returned, this is a finding.'
  desc 'fix', 'Disable dumpconf.
#  /etc/init.d/dumpconf stop
# insserv –r dumpconf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43046r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22404'
  tag rid: 'SV-45680r1_rule'
  tag stig_id: 'GEN003510'
  tag gtitle: 'GEN003510'
  tag fix_id: 'F-39078r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

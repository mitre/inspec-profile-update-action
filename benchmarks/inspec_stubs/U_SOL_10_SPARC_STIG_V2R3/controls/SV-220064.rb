control 'SV-220064' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', '# svcprop -p defaults svc:/network/inetd | grep tcp_wrappers
 
This should return a line with the following:

defaults/tcp_wrappers boolean true

If the above line contains the word false, this is a finding.'
  desc 'fix', 'Enable tcp_wrappers.
# svccfg -s svc:/network/inetd setprop defaults/tcp_wrappers=true
# svcadm refresh inetd'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21773r485507_chk'
  tag severity: 'medium'
  tag gid: 'V-220064'
  tag rid: 'SV-220064r603265_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21772r485508_fix'
  tag 'documentable'
  tag legacy: ['V-940', 'SV-28459']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

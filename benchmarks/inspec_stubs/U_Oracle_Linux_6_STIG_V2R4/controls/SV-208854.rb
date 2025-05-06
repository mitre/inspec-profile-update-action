control 'SV-208854' do
  title 'The system must not accept ICMPv4 redirect packets on any interface.'
  desc 'Accepting ICMP redirects has few legitimate uses. It should be disabled unless it is absolutely required.'
  desc 'check', 'The status of the "net.ipv4.conf.all.accept_redirects" kernel parameter can be queried by running the following command: 

$ sysctl net.ipv4.conf.all.accept_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 

$ grep net.ipv4.conf.all.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.conf.all.accept_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.accept_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.accept_redirects = 0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9107r357542_chk'
  tag severity: 'medium'
  tag gid: 'V-208854'
  tag rid: 'SV-208854r603263_rule'
  tag stig_id: 'OL6-00-000084'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9107r357543_fix'
  tag 'documentable'
  tag legacy: ['V-50971', 'SV-65177']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

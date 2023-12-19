control 'SV-208863' do
  title 'The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.'
  desc 'check', 'The status of the "net.ipv4.conf.all.rp_filter" kernel parameter can be queried by running the following command: 

$ sysctl net.ipv4.conf.all.rp_filter

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 

$ grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.conf.all.rp_filter" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.rp_filter=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.rp_filter = 1)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9116r357569_chk'
  tag severity: 'medium'
  tag gid: 'V-208863'
  tag rid: 'SV-208863r603263_rule'
  tag stig_id: 'OL6-00-000096'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9116r357570_fix'
  tag 'documentable'
  tag legacy: ['SV-64891', 'V-50685']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

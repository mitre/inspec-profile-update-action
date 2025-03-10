control 'SV-208853' do
  title 'The system must not accept IPv4 source-routed packets on any interface.'
  desc 'Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.'
  desc 'check', 'The status of the "net.ipv4.conf.all.accept_source_route" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_source_route

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.accept_source_route /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.conf.all.accept_source_route" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.accept_source_route=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.accept_source_route = 0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9106r357539_chk'
  tag severity: 'medium'
  tag gid: 'V-208853'
  tag rid: 'SV-208853r793638_rule'
  tag stig_id: 'OL6-00-000083'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9106r357540_fix'
  tag 'documentable'
  tag legacy: ['V-50969', 'SV-65175']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

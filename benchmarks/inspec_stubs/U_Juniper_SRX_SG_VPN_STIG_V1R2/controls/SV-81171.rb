control 'SV-81171' do
  title 'The Juniper SRX Services Gateway VPN must terminate all network connections associated with a communications session at the end of the session.'
  desc 'Idle TCP sessions can be susceptible to unauthorized access and hijacking attacks. By default, routers do not continually test whether a previously connected TCP endpoint is still reachable. If one end of a TCP connection idles out or terminates abnormally, the opposite end of the connection may still believe the session is available. These “orphaned” sessions use up valuable router resources and can also be hijacked by an attacker. To mitigate this risk, routers must be configured to send periodic keep alive messages to check that the remote end of a session is still connected. If the remote device fails to respond to the TCP keep alive message, the sending router will clear the connection and free resources allocated to the session.

The TCP keep-alive for remote access is implemented in the Juniper SRX Firewall STIG.'
  desc 'check', 'Ask the site representative which proposal implements Suite B.

[edit]
show security ike gateway <ike-peer-name>

View the configured options.

If the dead-peer-detection is configured, this is a finding.'
  desc 'fix', 'For site-to-site VPN, configure an Internet Key Exchange (IKE) gateway that includes dead-peer-detection parameters such as in the following example.

set security ike gateway IKE-PEER ike-policy IKE-POLICY
set security ike gateway IKE-PEER address <Peer IP Address>
set security ike gateway IKE-PEER dead-peer-detection always-send
set security ike gateway IKE-PEER dead-peer-detection interval 10
set security ike gateway IKE-PEER dead-peer-detection threshold 2
set security ike gateway IKE-PEER local-identity inet <IPv4 Address in Certificate>
set security ike gateway IKE-PEER remote-identity inet <IPv4 Address in Remote
Certificate>
set security ike gateway IKE-PEER external-interface <interface name>
set security ike gateway IKE-PEER version v2-only

For dynamic (remote access) VPN, the TCP keep-alive for remote access is implemented in the Juniper SRX Firewall STIG.'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67307r1_chk'
  tag severity: 'low'
  tag gid: 'V-66681'
  tag rid: 'SV-81171r1_rule'
  tag stig_id: 'JUSX-VN-000022'
  tag gtitle: 'SRG-NET-000213'
  tag fix_id: 'F-72757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

control 'SV-207221' do
  title 'The VPN Gateway must terminate all network connections associated with a communications session at the end of the session.'
  desc 'Idle TCP sessions can be susceptible to unauthorized access and hijacking attacks. By default, routers do not continually test whether a previously connected TCP endpoint is still reachable. If one end of a TCP connection idles out or terminates abnormally, the opposite end of the connection may still believe the session is available. These “orphaned” sessions use up valuable router resources and can be hijacked by an attacker. To mitigate this risk, routers must be configured to send periodic keep alive messages to check that the remote end of a session is still connected. If the remote device fails to respond to the TCP keep alive message, the sending router will clear the connection and free resources allocated to the session.'
  desc 'check', 'Verify the VPN Gateway terminates all network connections associated with a communications session at the end of the session.

If the VPN Gateway does not terminate all network connections associated with a communications session at the end of the session, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to terminate all network connections associated with a communications session at the end of the session.'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7481r378284_chk'
  tag severity: 'low'
  tag gid: 'V-207221'
  tag rid: 'SV-207221r608988_rule'
  tag stig_id: 'SRG-NET-000213-VPN-000720'
  tag gtitle: 'SRG-NET-000213'
  tag fix_id: 'F-7481r378285_fix'
  tag 'documentable'
  tag legacy: ['SV-106259', 'V-97121']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

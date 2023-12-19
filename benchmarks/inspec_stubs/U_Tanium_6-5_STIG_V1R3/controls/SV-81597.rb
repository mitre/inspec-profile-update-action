control 'SV-81597' do
  title 'Firewall rules must be configured on the Tanium Server for Server-to-Zone Server communications.'
  desc "If you are using the Tanium Zone Server to proxy traffic from Tanium-managed computers on less trusted network segments to the Tanium Server on the core network, then the Tanium Zone Server Hub, typically installed to the Tanium Server device, must be able to connect to the Zone Server(s) in the DMZ. This is the only configuration that requires you to allow outbound traffic on port 17472 from the Tanium Server device. The ZoneServerList.txt configuration file located in the Tanium Zone Server Hub's installation folder identifies the addresses of the destination Zone Servers. See the Zone Server Configuration page for more details.

Port Needed: Tanium Server to Zone Server over TCP port 17472.

Network firewall rules:

Allow TCP traffic on port 17472 from the Zone Server Hub, usually the Tanium Server device, to the destination DMZ devices(s) hosting the Zone Server(s).

Endpoint firewall rules - for additional security, configure the following endpoint firewall rules:

Allow TCP traffic outbound on port 17472 from only the Zone Server Hub process running on the Tanium Server device
Allow TCP traffic inbound on port 17472 to only the Zone Server process running on the designated Zone Server device(s). 

https://kb.tanium.com/Port_Configuration_v6.5"
  desc 'check', 'Note: If a Zone Server is not being used, this is Not Applicable.

Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Server.

Access the host-based firewall configuration on the Tanium Server.

Validate a rule exists for the following:
Port Needed: Tanium Server to Zone Server over TCP port 17472.

If a host-based firewall rule does not exist to allow TCP port 17472, bi-directionally, from Tanium Server to the Tanium Zone Server, this is a finding.'
  desc 'fix', 'Configure host-based firewall rules on the Tanium Zone server to include the following required traffic:

Allow Tanium Server to Zone Server over TCP port 17472.

Configure the network firewall to allow the above traffic.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67107'
  tag rid: 'SV-81597r1_rule'
  tag stig_id: 'TANS-SV-000033'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-73207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

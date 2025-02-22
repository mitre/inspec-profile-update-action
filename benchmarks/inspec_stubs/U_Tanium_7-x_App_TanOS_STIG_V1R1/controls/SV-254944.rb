control 'SV-254944' do
  title 'Firewall rules must be configured on the Tanium Server for Server-to-Zone Server communications.'
  desc "If using the Tanium Zone Server to proxy traffic from Tanium-managed computers on less trusted network segments to the Tanium Server on the core network, then the Tanium Zone Server Hub, typically installed to the Tanium Server device must be able to connect to the Zone Server(s) in the DMZ. This is the only configuration that requires outbound traffic to be allowed on port 17472 from the Tanium Server device. The ZoneServerList.txt configuration file located in the Tanium Zone Server Hub's installation folder identifies the addresses of the destination Zone Servers. See the Zone Server Configuration page for more details.

Port Needed: Tanium Server to Zone Server over TCP port 17472.

Network firewall rules:

Allow TCP traffic on port 17472 from the Zone Server Hub, usually the Tanium Server device, to the destination DMZ devices(s) hosting the Zone Server(s).

Endpoint firewall rules—for additional security, configure the following endpoint firewall rules:

Allow TCP traffic outbound on port 17472 from only the Zone Server Hub process running on the Tanium Server device.

Allow TCP traffic inbound on port 17472 to only the Zone Server process running on the designated Zone Server device(s).

https://docs.tanium.com/platform_install/platform_install/reference_network_ports.html."
  desc 'check', 'Note: If a Zone Server is not being used, this is Not Applicable.

Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Server.

1. Access the Tanium Server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Access the host-based firewall configuration on the Tanium Server.

4. Validate a rule exists for the following:

4A. Port Needed: Tanium Server to Zone Server over TCP port 17472.

Note: By default, the Zone Server uses 17472 for traffic from Zone Server Hubs and Tanium Clients. However, as a best practice to improve the security of the Zone Server, different ports can be configured for the hubs and clients.

If a host-based firewall rule does not exist to allow TCP port 17472 or other defined port, bidirectionally, from Tanium Server to the Tanium Zone Server, this is a finding.'
  desc 'fix', '1. Configure host-based firewall rules on the Tanium Zone server to include the following required traffic:

1A. Allow Tanium Server to Zone Server over TCP port 17472.

2. Configure the network firewall to allow the above traffic.

Note: By default, the Zone Server uses 17472 for traffic from Zone Server Hubs and Tanium Clients. However, as a best practice to improve the security of the Zone Server, different ports can be configured for the hubs and clients.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58557r867730_chk'
  tag severity: 'medium'
  tag gid: 'V-254944'
  tag rid: 'SV-254944r867732_rule'
  tag stig_id: 'TANS-AP-000985'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-58501r867731_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

control 'SV-81521' do
  title 'Firewall rules must be configured on the Tanium Server for Server-to-Database communications.'
  desc 'The Tanium Server can use either a SQL Server RDBMS installed locally to the same device as the Tanium Server application or a remote dedicated or shared SQL Server instance. Using a local SQL Server database typically requires no changes to network firewall rules since all communication remains on the Tanium application server device. To access database resources installed to a remote device, however, the Tanium Server service communicates over the port reserved for SQL, by default port 1433, to the database.

Port Needed: Tanium Server to Remote SQL Server over TCP port 1433.

Network firewall rules:

Allow TCP traffic on port 1433 from the Tanium Server device to the remote device hosting the SQL Server RDBMS.

https://kb.tanium.com/Port_Configuration_v6.5'
  desc 'check', 'Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Server.

Access the host-based firewall configuration on the Tanium Server.

Validate a rule exists for the following:
Port Needed: Tanium Server to Remote SQL Server over TCP port 1433.

If a host-based firewall rule does not exist to allow Tanium Server to Remote SQL Server over TCP port 1433, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:
Allow traffic from Tanium Server to Remote SQL Server over TCP port 1433.

If a network firewall rule does not exist to allow traffic from Tanium Server to Remote SQL Server over TCP port 1433, this is a finding.'
  desc 'fix', 'Configure host-based and network firewall rules as required.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67031'
  tag rid: 'SV-81521r1_rule'
  tag stig_id: 'TANS-DB-000005'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-73131r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

control 'SV-213990' do
  title 'SQL Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'SQL Server must only use approved network communication libraries, ports, and protocols. 
 
Obtain a list of all approved network libraries, communication ports, and protocols from the server documentation. 
 
Verify that the protocols are enabled for the instance. 
 
If any ports or protocols are used that are not specifically approved in the server documentation, this is a finding.'
  desc 'fix', 'Assign the approved TCP/IP port number to the SQL Server Database Engine. 
1. In SQL Server Configuration Manager, in the console pane, expand SQL Server Network Configuration, expand Protocols for <instance name>, and then double-click "TCP/IP". 
2. In the "TCP/IP Properties" dialog box, on the "IP Addresses" tab, several IP addresses appear in the format IP1, IP2, up to IPAll. One of these is for the IP address of the loopback adapter, 127.0.0.1. Additional IP addresses appear for each IP Address on the computer. (You will probably see both IP version 4 and IP version 6 addresses.) Right-click each address, and then click "Properties" to identify the IP address that you want to configure. 
3. If the "TCP Dynamic Ports" dialog box contains "0", indicating the Database Engine is listening on dynamic ports, delete the "0". 
4. In the "IPn Properties area" box, in the "TCP Port" box, type the port number you want this IP address to listen on, and then click "OK". 
5. In the console pane, click "SQL Server Services". 
6. In the details pane, right-click "SQL Server (<instance name>)" and then click "Restart", to stop and restart SQL Server. 
 
To disable a server network protocol for an instance: 
1. In SQL Server Configuration Manager, in the console pane, expand SQL Server Network Configuration. 
2. In the console pane, click "Protocols" for <instance name>. 
3. In the details pane, right-click the protocol you want to change, and then click "Enable" or "Disable". 
4. In the console pane, click "SQL Server Services". 
5. In the details pane, right-click "SQL Server (<instance name>)", and then click "Restart", to stop and restart the SQL Server service.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15207r313753_chk'
  tag severity: 'medium'
  tag gid: 'V-213990'
  tag rid: 'SV-213990r879756_rule'
  tag stig_id: 'SQL6-D0-011900'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-15205r313754_fix'
  tag 'documentable'
  tag legacy: ['SV-93947', 'V-79241']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

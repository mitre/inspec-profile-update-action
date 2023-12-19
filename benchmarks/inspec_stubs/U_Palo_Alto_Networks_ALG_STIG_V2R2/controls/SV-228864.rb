control 'SV-228864' do
  title 'The Palo Alto Networks security platform must be configured to integrate with a system-wide intrusion detection system.'
  desc 'Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack.

Integration of the Palo Alto Networks security platform with a system-wide intrusion detection system supports continuous monitoring and incident response programs. This requirement applies to monitoring at internal boundaries using TLS gateways, web content filters, email gateways, and other types of ALGs. The Palo Alto Networks security platform can work as part of the network monitoring capabilities to off-load inspection functions from the external boundary IDPS by performing more granular content inspection of protocols at the upper layers of the OSI reference model.

NetFlow is an industry-standard protocol that enables the firewall to record statistics on the IP traffic that traverses its interfaces. The  Palo Alto Networks security platform can export the statistics as NetFlow fields to a NetFlow collector. The NetFlow collector is a server you use to analyze network traffic for security, administration, accounting and troubleshooting purposes.'
  desc 'check', 'Go to Device >> Server Profiles >> NetFlow
If no NetFlow Server Profiles are configured, this is a finding.

This step assumes that it is one of the Ethernet interfaces that is being monitored.
The verification is the same for Ethernet, VLAN, Loopback and Tunnel interfaces.
Ask the administrator which interface is being monitored; there may be more than one.
Go to Network >> Interfaces >> Ethernet
Select the interface that is being monitored.
If the "Netflow Profile" field is "None", this is a finding.'
  desc 'fix', 'To create a NetFlow Server Profile:
Go to Device >> Server Profiles >> NetFlow
Select "Add".
In the "NetFlow Server Profile" window, complete the required fields.
In the "Name" field, enter the name of the NetFlow Server Profile.
In the "Minutes" field, enter the number of minutes after which the NetFlow template is refreshed. 
In the "Packets" field, enter the number of packets after which the NetFlow template is refreshed.
In the "Active Timeout" field, enter the frequency (in minutes) the device exports records.
Select the "PAN-OS Field Types" check box to export "App-ID" and "User-ID" fields.
Select "Add" to add a NetFlow collector.
In the "Name" field, enter the name of the server.
In the "NetFlow Server" field, enter the hostname or IP address of the server.
In the "Port" field enter the port used by the NetFlow collector (default 2055).
Select "OK".

Assign the NetFlow server profile to the interfaces that carry the traffic to be analyzed.  These steps assume that it is one of the Ethernet interfaces.  The configuration is the same for Ethernet, VLAN, Loopback, and Tunnel interfaces.
Go to Network >> Interfaces >> Ethernet
Select the interface that the traffic traverses.
In the "Ethernet Interface" window, in the "Netflow Profile" field, select the configured Netflow Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31099r513887_chk'
  tag severity: 'low'
  tag gid: 'V-228864'
  tag rid: 'SV-228864r557387_rule'
  tag stig_id: 'PANW-AG-000111'
  tag gtitle: 'SRG-NET-000383-ALG-000135'
  tag fix_id: 'F-31076r513888_fix'
  tag 'documentable'
  tag legacy: ['SV-77099', 'V-62609']
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end

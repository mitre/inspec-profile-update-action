control 'SV-207705' do
  title 'Palo Alto Networks security platform components, including sensors, event databases, and management consoles must integrate with a network-wide monitoring capability.'
  desc "An integrated, network-wide intrusion detection capability increases the ability to detect and prevent sophisticated distributed attacks based on access patterns and characteristics of access.

Integration is more than centralized logging and a centralized management console. The enclave's monitoring capability may include multiple sensors, IPS, sensor event databases, behavior-based monitoring devices, application-level content inspection systems, malicious code protection software, scanning tools, audit record monitoring software, and network monitoring software. Some tools may monitor external traffic while others monitor internal traffic at key boundaries. 

These capabilities may be implemented using different devices and therefore can have different security policies and severity-level schema. This is valuable because content filtering, monitoring, and prevention can become a bottleneck on the network if not carefully configured."
  desc 'check', 'Go to Device >> Server Profiles >> NetFlow
If no NetFlow Server Profiles are configured, this is a finding.

This step assumes that it is an Ethernet interface that is being monitored.  The verification is the same for Ethernet, VLAN, Loopback and Tunnel interfaces.  Ask the Administrator which interface is being monitored; there may be more than one.
Go to Network >> Interfaces >> Ethernet
Select the interface that is being monitored.
If the "NetFlow Profile" field is "None", this is a finding.'
  desc 'fix', 'To create a NetFlow Server Profile:
Go to Device >> Server Profiles >> NetFlow
Select Add.
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

Assign the NetFlow server profile to the interfaces that carry the traffic to be analyzed.  These steps assume that it is one of the Ethernet interfaces.  The configuration is the same for Ethernet, VLAN, Loopback and Tunnel interfaces.
Go to Network >> Interfaces >> Ethernet
Select the interface that the traffic traverses.
In the "Ethernet Interface" window, in the "NetFlow Profile" field, select the configured NetFlow Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7959r358448_chk'
  tag severity: 'medium'
  tag gid: 'V-207705'
  tag rid: 'SV-207705r557390_rule'
  tag stig_id: 'PANW-IP-000045'
  tag gtitle: 'SRG-NET-000383-IDPS-00208'
  tag fix_id: 'F-7959r358449_fix'
  tag 'documentable'
  tag legacy: ['SV-77171', 'V-62681']
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end

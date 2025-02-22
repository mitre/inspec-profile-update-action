control 'SV-207689' do
  title 'The Palo Alto Networks security platform must produce audit records containing information to establish the source of the event, including, at a minimum, originating source address.'
  desc 'Associating the source of the event with detected events in the logs provides a means of investigating an attack or suspected attack.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

Palo Alto Networks security platform has four options for the source of log records - "FQDN", "hostname", "ipv4-address", and "ipv6-address".  This requirement only allows the use of "ipv4-address" and "ipv6-address" as options.'
  desc 'check', 'Go to Device >> Setup >> Management
In the "General Settings" window, if the "hostname" field does not contain a unique identifier, this is a finding.

Go to Device >> Setup >> Management
In the "Logging and Reporting Settings" pane, if the "Send Hostname in Syslog" does not show either "ipv4-address" or "ipv6-address", this is a finding.'
  desc 'fix', 'Set a unique hostname.
Go to Device >> Setup >> Management
In the "General Settings" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "General Settings" window, in the "hostname" field; enter a unique hostname.
Select "OK".

Configure the device to send either the FQDN, hostname,  ipv4-address, or  ipv6-address with log messages.
Device >> Setup >> Management
Click the "Edit" icon in the "Logging and Reporting Settings" section.
Select the "Log Export and Reporting" tab.
Select one of the following options from the "Send Hostname" in the "Syslog" drop-down list:
ipv4-address —Uses the IPv4 address of the interface used to send logs on the device. By default, this is the management interface of the device.
ipv6-address —Uses the IPv6 address of the interface used to send logs on the device. By default, this is the management interface of the device.  
Note that the last two selections must be consistent with the IP address used by the management interface.
Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7943r358400_chk'
  tag severity: 'medium'
  tag gid: 'V-207689'
  tag rid: 'SV-207689r557390_rule'
  tag stig_id: 'PANW-IP-000007'
  tag gtitle: 'SRG-NET-000077-IDPS-00062'
  tag fix_id: 'F-7943r358401_fix'
  tag 'documentable'
  tag legacy: ['V-62649', 'SV-77139']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end

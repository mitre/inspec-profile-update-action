control 'SV-228643' do
  title 'The Palo Alto Networks security platform must produce audit log records containing information (FQDN, unique hostname, management IP address) to establish the source of events.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.  The source may be a component, module, or process within the device or an external session, administrator, or device.  Associating information about where the source of the event occurred provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.

The device must have a unique hostname that can be used to identify the device; fully qualified domain name (FQDN), hostname, or management IP address is used in audit logs to identify the source of a log message.'
  desc 'check', 'Go to Device >> Setup >> Management
In the "General Settings" window, if the "hostname" field does not contain a unique identifier, this is a finding.

Go to Device >> Setup >> Management
In the "Logging and Reporting Settings" pane, if the "Send Hostname in Syslog" does not show either "FQDN", "hostname", "ipv4-address", or "ipv6-address", this is a finding.'
  desc 'fix', 'Set a unique hostname.
Go to Device >> Setup >> Management
in the "General Settings" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "General Settings" window, in the "hostname" field; enter a unique hostname. 
Select "OK".

Configure the device to send the FQDN, hostname, ipv4-address, or ipv6-address with log messages.
Device >> Setup >> Management
Click the "Edit" icon in the "Logging and Reporting Settings" section.
Select the "Log Export and Reporting" tab.
Select one of the following options from the "Send Hostname in the Syslog" drop-down list:
FQDN — (the default) Concatenates the hostname and domain name defined on the sending device.
hostname — Uses the hostname defined on the sending device.
ipv4-address —Uses the IPv4 address of the interface used to send logs on the device. By default, this is the management interface of the device.
ipv6-address —Uses the IPv6 address of the interface used to send logs on the device. By default, this is the management interface of the device. 
Note that the last two selections must be consistent with the IP address used by the management interface.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30878r513533_chk'
  tag severity: 'low'
  tag gid: 'V-228643'
  tag rid: 'SV-228643r513535_rule'
  tag stig_id: 'PANW-NM-000029'
  tag gtitle: 'SRG-APP-000098-NDM-000228'
  tag fix_id: 'F-30855r513534_fix'
  tag 'documentable'
  tag legacy: ['SV-77203', 'V-62713']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end

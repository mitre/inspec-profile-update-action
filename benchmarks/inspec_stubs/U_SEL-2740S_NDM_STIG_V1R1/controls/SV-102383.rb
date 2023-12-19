control 'SV-102383' do
  title 'The SEL-2740S must be configured to send log data to a Syslog server or collected by another parent OTSDN Controller.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained.'
  desc 'check', %q(Ensure SEL-2740S Syslog servers are configured by doing the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Go to the "Configuration Objects" page.
3. Check Syslog Server IP addresses are in the settings fields for the switch node in log services.
4. Check Syslog flows exist and are accurate for the SEL-2740S DUT and additional neighbor devices' flows exist and are correct.

If the SEL-2740S is not configured with Syslog server entries to ensure auditability, this is a finding.)
  desc 'fix', %q(To collect logs using the OTSDN controller, do the following:
1. Go to the "Log Settings" page.
2. Select the Primary entry in the Logging table.
3. Click the "Add" icon (A) in the "Log Services" pane.
4. Select Syslog Server (B) from the menu to display a new Syslog Server Log Service box.
5. Click the "Syslog Server" box to display a blue border around the box.
6. Enter Settings (1) through (4) in the appropriate boxes.
7. Click "Submit".

Use the OTSDN Controller to Syslog the events to a central Security Information and Event Manager (SIEM).
Option 2
To configure the SEL-2740S to send logs to a syslog server:
1. Go to the configuration object setting page.
2. Select syslog under the log services for the desired switch.
3. Enter the settings desired for the syslog server IP address and severity level to send to this destination.
4. Repeat for amount of desired log servers as the SEL-2740S supports up to three destinations.

To create the flow rule(s) for Syslog traffic:
1. Log in to OTSDN Controller with Permission Level 3.
2. Identify or create the Configuration Port to use for the path to Syslog Server.
3. Identify or create the Configuration Link to use for the path to Syslog Server.

Create the Flow Rule for the SEL-2740S' Syslog traffic:
1. Click "Flow Entries" in Navigation Menu.
2. Click "Add Flow" button.
3. Enter General setting values for "Switch" Enable.  Optional enter General settings for "Table ID", "Priority", "Idle Timeout", and "Hard Timeout".
4. For Syslog traffic, enter appropriate "Match Field" values for "ARP Opcode" (Request or Reply), "ARP Source", "ARP Target", "Communication Service Type (CST) Match", "Ethernet Destination", "Ethernet Source", "Ethernet Type", "InPort", "IP Proto", "IPv4 Destination", "IPv4 Source", "TCP Destination", "TCP Source", "UDP Destination", "UDP Source", "VLAN Priority", and/or "VLAN Virtually ID".
5. Enter appropriate Write-Actions for "Pop VLAN ID", "Push VLAN ID", "Set VLAN ID", "Set VLAN Priority", "Set Queue", "Group by Alias or Value", and/or "Output by Alias or "Value".
6. Click "Submit".)
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91591r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92295'
  tag rid: 'SV-102383r1_rule'
  tag stig_id: 'SELS-ND-000430'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-98533r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end

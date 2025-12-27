control 'SV-77449' do
  title 'Riverbed Optimization System (RiOS) must authenticate  NTP server before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', %q(Verify that RiOS is configured to authenticate NTP server before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based (NTP portion of the requirement).

Navigate to the device CLI
Type: enable
Type: show ntp all
Verify that at least two NTP Servers are configured
Type: show ntp authentication
Verify the "Trusted Keys" are defined for use with NTP

-- or --

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Date and Time
Verify that at least two servers are configured in the section "Requested Servers"

If no NTP Servers are visible after the command 'show ntp all' or on "Requested Servers", this is a finding.)
  desc 'fix', %q(Configure RiOS to authenticate NTP server before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based (NTP portion of the requirement).

Navigate to the device CLI
Type: enable
Type: conf t
Type: ntp server <hostname | ip address>
Type: ntp server <hostname | ip address> 
Type: ntp authentication key <key id> secret 7 <encrypted string>
Type: ntp authentication trustedkeys <key id>

Configure 2 NTP Servers
Type: ntp enable
Type: write memory

-- or --

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Date and Time
Click "Add a New NTP Authentication Key"
Set the value of "Key ID" to the required setting (1 to 65534)
Set the value of "Key Type" to MD5 or SHA
Set the value of "Secret" to the required setting for the NTP server
Click "Add"
Click '"Add" a New NTP Server'
Set the value of "Hostname or IP Address" to the required NTP Server
Set the value of "Version" to 3 or 4 depending on the ntp server
Set the value of "Key ID" to a value on the trusted key list
Set the value of "Enabled/Disabled" to "Enabled"
Click "Add"
Configure 2 NTP Servers
Click "Use NTP Time Synchronization"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently)
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62959'
  tag rid: 'SV-77449r1_rule'
  tag stig_id: 'RICX-DM-000111'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-68877r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

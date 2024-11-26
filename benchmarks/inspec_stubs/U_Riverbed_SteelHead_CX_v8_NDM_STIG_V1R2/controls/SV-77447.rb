control 'SV-77447' do
  title 'Riverbed Optimization System (RiOS) must authenticate SNMP server before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Verify that RiOS is configured to authenticate SNMP server before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based (SNMP portion of the requirement).

Navigate to the device Management Console
Navigate to Configure >> System Settings >> SNMP Basic
Verify that at least one "Host" is defined under "Trap Receivers"
Verify that the "Host" defined under "Trap Receivers" is set for "Version" v3
Verify that "Enable SNMP Traps" is set

If no "Host" exists under "Trap Receivers or the "Host" is not "Version" v3 and/or "Enable SNMP Traps" is not set, this is a finding.'
  desc 'fix', 'Configure RiOS to authenticate SNMP server before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based (SNMP portion of the requirement).

Navigate to the device Management Console
Navigate to Configure >> System Settings >> SNMP Basic
Click "Add a New Trap Receiver"
Set "Receiver" to the IP address of the trap receiver
Set "Destination Port" to the listening port on the trap receiver
Set "Receiver Type" to v3
Set "Remote User" to the SNMP user on the trap receiver
Set "Authentication" to "Supply a Key"
Set "Authentication Protocol" to "MD5" or "SHA"
Set "Security Level" to "AuthPriv"
Set "Privacy Protocol" to "AES"
Set "Privacy" to "Same as Authentication Key"
Set "MD5/SHA Key" to the proper authentication key
Set "Enable Receiver"
Click "Add"
Click "Enable SNMP Traps"
Click "Apply"

Navigate to the top of the web page and click "Save" to save these settings permanently.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63709r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62957'
  tag rid: 'SV-77447r1_rule'
  tag stig_id: 'RICX-DM-000110'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-68875r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

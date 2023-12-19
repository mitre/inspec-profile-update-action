control 'SV-77445' do
  title 'Riverbed Optimization System (RiOS) must authenticate network management endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', "Verify that RiOS is configured to authenticate network management endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based (network management portion of the requirement).

Navigate to the device CLI
Type: enable
Type: show configuration full
Verify that 'no telnet-server enable' is in the configuration
Verify that 'ssh server enable' is set in the configuration
Verify that 'web enable' is in the configuration
Verify that 'no web http enable' is in the configuration
Verify that 'web https enable' is in the configuration

If any one of the above settings is missing from the configuration, this is a finding."
  desc 'fix', 'Configure RiOS to Authenticate network management endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based (network management portion of the requirement).

Navigate to the device CLI
Type: enable
Type: config t
Type: no telnet-server enable
Type: ssh server enable
Type: ssh server allowed-cyphers aes128-cbc, 3des-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr
Type: web enable
Type: no web http enable
Type: web https enable
Type: write memory
Type: exit
Type: exit'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62955'
  tag rid: 'SV-77445r1_rule'
  tag stig_id: 'RICX-DM-000109'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-68873r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

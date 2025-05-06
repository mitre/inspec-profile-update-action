control 'SV-88725' do
  title 'The Cisco IOS XE router must authenticate network management, SNMP, and NTP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to secure connections.

The configuration should look similar to the example below:

ip ssh version 2
ip ssh dh min size 2048

ntp authentication-key 1 md5 075B706F471A1A0A464058 7
ntp authenticate
ntp trusted-key 1
ntp peer 192.168.2.1 key 1

snmp-server user new-user new-group v3 auth sha password priv aes 128 Cisco

If the Cisco IOS XE router is not configured to secure all management connections, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router so that connections are secure.

The configuration should look similar to the example below:

ip ssh version 2
ip ssh dh min size 2048

ntp authentication-key 1 md5 075B706F471A1A0A464058 7
ntp authenticate
ntp trusted-key 1
ntp peer 192.168.2.1 key 1

snmp-server user new-user new-group v3 auth sha password priv aes 128 Cisco'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74141r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74051'
  tag rid: 'SV-88725r2_rule'
  tag stig_id: 'CISR-ND-000112'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-80593r4_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

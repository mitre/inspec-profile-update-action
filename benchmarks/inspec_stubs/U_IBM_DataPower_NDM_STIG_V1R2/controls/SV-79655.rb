control 'SV-79655' do
  title 'The DataPower Gateway must use SNMPv3.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'For SNMP, go to Administration >> Access >> SNMP Settings. Ensure the SNMP v3 Security Level is set to Authenticate. If it is not, this is a finding.'
  desc 'fix', 'The browser, SSH, and XML Management network interfaces are set to SSL/TLS and require authentication by default. For SNMP, go to Administration >> Access >> SNMP Settings. Set SNMP v3 Security Level to Authenticate. Create one or more new SNMPv3 users that employ Authentication (may be password or key). Network transport for SNMP uses TLS by default.'
  impact 0.7
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65793r1_chk'
  tag severity: 'high'
  tag gid: 'V-65165'
  tag rid: 'SV-79655r1_rule'
  tag stig_id: 'WSDP-NM-000112'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-71105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

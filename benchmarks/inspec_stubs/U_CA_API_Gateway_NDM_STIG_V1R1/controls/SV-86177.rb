control 'SV-86177' do
  title 'The CA API Gateway must authenticate SNMP endpoint devices before establishing a network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Verify the "snmptrap" shell command used to emit SNMP TRAPS to the Network Management Station is using Version 3 with User Authentication for each potential trap source identified in this document. "snmptrap -v 3 -a SHA -A mypassword -x AES -X mypassword -l authPriv -u traptest -e 0x8000000001020304 localhost REQUIRED_TRAP_OID"

If SNMP Version 3 is not being used, this is a finding.'
  desc 'fix', 'Change the "snmptrap" command at each source to use encryption/authentication (Version 3) IE: "snmptrap -v 3 -a SHA -A mypassword -x AES -X mypassword -l authPriv -u traptest -e 0x8000000001020304 localhost REQUIRED_TRAP_OID"'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71553'
  tag rid: 'SV-86177r1_rule'
  tag stig_id: 'CAGW-DM-000270'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-77873r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

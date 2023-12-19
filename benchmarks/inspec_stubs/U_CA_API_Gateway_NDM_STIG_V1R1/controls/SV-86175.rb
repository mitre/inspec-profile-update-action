control 'SV-86175' do
  title 'The CA API Gateway must authenticate NTP endpoint devices before establishing a network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Verify "server" lines in the "/etc/ntp.conf" file are all marked with "autokey". Perform the command "ntpq -p" to show peer functioning.

If the "server" lines in the "/etc/ntp.conf" file are not marked with "autokey", this is a finding. 

If the command "ntpq -p" does not show peers functioning, this is a finding.'
  desc 'fix', 'Configure Gateway to use public key (autokey in NTP terminology) authentication. See: http://support.ntp.org/bin/view/Support/ConfiguringAutokey'
  impact 0.3
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71923r1_chk'
  tag severity: 'low'
  tag gid: 'V-71551'
  tag rid: 'SV-86175r1_rule'
  tag stig_id: 'CAGW-DM-000260'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-77871r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

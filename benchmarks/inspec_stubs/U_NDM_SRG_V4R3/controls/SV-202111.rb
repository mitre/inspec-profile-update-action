control 'SV-202111' do
  title 'The network device must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the network device configuration to verify SNMP messages are authenticated using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).

If the network device is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2237r381953_chk'
  tag severity: 'medium'
  tag gid: 'V-202111'
  tag rid: 'SV-202111r879768_rule'
  tag stig_id: 'SRG-APP-000395-NDM-000310'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-2238r381954_fix'
  tag 'documentable'
  tag legacy: ['SV-69501', 'V-55255']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

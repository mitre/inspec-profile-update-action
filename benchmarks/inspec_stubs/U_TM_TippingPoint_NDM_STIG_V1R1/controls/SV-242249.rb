control 'SV-242249' do
  title 'The TippingPoint SMS must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'In the SMS client, ensure a SNMPv3 trap destination and SNMPv3 Requests are configured.

1. Select Admin and Server Properties.
2. Select SNMP.

If an NMS Trap Destination is not configured, or if SNMPv3 requests are not configured, or if the SNMPv3 protocol does not use as least AES-128 for privacy and SHA1 for authentication, then this is a finding.'
  desc 'fix', "In the SMS client, ensure a SNMPv3 trap destination is configured.

1. Select Admin and Server Properties.
2. Select SNMP.
3. Click Add.
4. Enter the IPv4 or IPv6 address, Version 3, with the username, and authPriv keys configured that match the site's required attributes. The authentication must at least be SHA1 and the privacy must be at least AES 128.
5. Select edit under the SNMP tab. 
6. Check enable SNMP requests.
7. Select only v3.
8. Enter the username and the authentication and privacy keys. The authentication must at least be SHA1 and the privacy must be at least AES 128. 
9. Select OK."
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45524r710752_chk'
  tag severity: 'high'
  tag gid: 'V-242249'
  tag rid: 'SV-242249r710754_rule'
  tag stig_id: 'TIPP-NM-000440'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-45482r710753_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

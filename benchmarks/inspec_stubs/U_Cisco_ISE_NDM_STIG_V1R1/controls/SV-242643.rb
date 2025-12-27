control 'SV-242643' do
  title 'The Cisco ISE must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If the Cisco ISE does not generate unique session identifiers using a FIPS 140-2 approved RNG, this is a finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure DRBG is used for all RNG functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45918r714237_chk'
  tag severity: 'medium'
  tag gid: 'V-242643'
  tag rid: 'SV-242643r714239_rule'
  tag stig_id: 'CSCO-NM-000380'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-45875r714238_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

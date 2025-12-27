control 'SV-230961' do
  title 'Forescout must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the Forescout configuration to determine if the network device authenticates SNMP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "SNMP" tab.
3. Verify that the "SNMPv3" option is selected and the "HMAC-SHA" authentication protocol is selected.
4. Verify that the "use privacy" radio button is selected and "AES-128" is also selected from the drop-down box.

If Forescout does not authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC), this is a finding.'
  desc 'fix', 'Configure Forescout to authenticate SNMP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "SNMP" tab.
3. Ensure the "SNMPv3" option is selected and the "HMAC-SHA" authentication protocol is selected.
4. Ensure the "use privacy" radio button is selected and "AES-128" or higher is selected from the drop-down box.'
  impact 0.7
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33891r603722_chk'
  tag severity: 'high'
  tag gid: 'V-230961'
  tag rid: 'SV-230961r615886_rule'
  tag stig_id: 'FORE-NM-000350'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-33864r603723_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

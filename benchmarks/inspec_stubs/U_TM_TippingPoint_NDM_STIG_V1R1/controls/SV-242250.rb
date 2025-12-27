control 'SV-242250' do
  title 'The TippingPoint SMS must authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'In the SMS client, ensure NTP authentication is enabled.

1. Log in to the serial console or ESXi virtual console.
2. Run the command ntp-auth.

If NTP auth is not enabled for client and server, this is a finding.'
  desc 'fix', 'In the SMS client, ensure NTP authentication is enabled.

1. Log in to the serial console or ESXi virtual console.
2. Run the command ntp-auth.
3. Select "Y" to change the NTP Authentication settings.
4. Select “A”, enter a key ID.
5. Select "V" to add the key value.
6. Select "T" and ensure SHA1 is added.
7. Select "K" and enter the key ID number.
8. Select "U" and "E" for enable for client and server authentication.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45525r710755_chk'
  tag severity: 'high'
  tag gid: 'V-242250'
  tag rid: 'SV-242250r710757_rule'
  tag stig_id: 'TIPP-NM-000450'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-45483r710756_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

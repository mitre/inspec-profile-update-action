control 'SV-258602' do
  title 'If SNMP is used, the ICS must be configured to use SNMPv3 with FIPS-140-2/3 validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'If SNMP is not used, this is not applicable. 

In the ICS Web UI, navigate to System >> Log/Monitoring >> SNMP.

Under "SNMP version data", verify v2c is not selected.

If the ICS does not use properly configured SNMPv3, this is a finding.'
  desc 'fix', 'This is applicable if SNMP is enabled. Though the entire SNMP configuration is given to prevent misconfiguration, note that this requirement is focused on the use of v3.

In the ICS Web UI, navigate to System >> Log/Monitoring >> SNMP.
1. Under "SNMP version data", select v3.
2. Under "Agent Properties", select SNMP Queries.
3. Define the System Name.
4. Define the System Location.
5. Define the System Contact.
6. Under "SNMPv3 Configuration" and "User 1" type the username.
7. Select the "Security Level" of Auth, Priv.
8. Select SHA as the Auth Protocol.
9. Type the Auth password.
10. Select "CFB-AES-128" as the Priv Protocol.
11. Type the Priv password.
12. Under Optional Traps, select "Critical and Major log events".
13. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62342r930492_chk'
  tag severity: 'medium'
  tag gid: 'V-258602'
  tag rid: 'SV-258602r930494_rule'
  tag stig_id: 'IVCS-NM-000090'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-62251r930493_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

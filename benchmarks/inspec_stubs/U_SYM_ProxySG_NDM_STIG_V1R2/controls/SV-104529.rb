control 'SV-104529' do
  title 'Symantec ProxySG must configure SNMPv3 so that cryptographically-based bidirectional authentication is used.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Verify only SNMPv3 (which supports authentication) is configured on the Symantec ProxySG.

1. Log on to the Web Management Console.
2. Click Maintenance >> SNMP.
3. Ensure that only "Enable SNMPv3" is checked.
4. Click on "SNMPv3 Users" and ensure that a user exists in the list.

If SNMPv3 (which supports authentication) is not configured or is not the only one configured on the Symantec ProxySG, this is a finding.'
  desc 'fix', 'Enable only SNMPv3 (which supports authentication) on the Symantec ProxySG.

1. Log on to the Web Management Console.
2. Click Maintenance >> SNMP.
3. Uncheck "Enable SNMPv1" and "Enable SNMPv2c" and check "Enable SNMPv3".
4. Click on "SNMPv3 Users", click "New" and enter the desired username, credentials, and authorization settings, click "OK".
5. Click "SNMPv3 Traps", click "New", enter the IP address/FQDN for the SNMP receiver.
6. Click "OK", click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94699'
  tag rid: 'SV-104529r1_rule'
  tag stig_id: 'SYMP-NM-000240'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-100817r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

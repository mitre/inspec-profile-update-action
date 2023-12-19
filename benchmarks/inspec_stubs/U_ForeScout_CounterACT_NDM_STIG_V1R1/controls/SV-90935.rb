control 'SV-90935' do
  title 'CounterACT must authenticate SNMPv3 endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication. Use of non-secure versions of management protocols with well-known exploits puts the system at immediate risk.'
  desc 'check', 'Review the CounterACT configuration to determine if the network device authenticates SNMP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "SNMP" tab.
3. Verify that the "SNMPv3" option is selected and the "HMAC-SHA" authentication protocol is selected.
4. Verify that the "use privacy" radio button is selected and "AES-128" is also selected from the drop-down box.

If CounterACT does not authenticate the endpoint devices before establishing a connection using bidirectional authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure CounterACT to authenticate SNMP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "SNMP" tab.
3. Ensure that the "SNMPv3" option is selected and the "HMAC-SHA" authentication protocol is selected.
4. Ensure that the "use privacy" radio button is selected and "AES-128" is also selected from the drop-down box.'
  impact 0.7
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75933r1_chk'
  tag severity: 'high'
  tag gid: 'V-76247'
  tag rid: 'SV-90935r1_rule'
  tag stig_id: 'CACT-NM-000040'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-82883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

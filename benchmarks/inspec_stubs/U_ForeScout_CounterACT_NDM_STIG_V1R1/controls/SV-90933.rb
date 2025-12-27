control 'SV-90933' do
  title 'CounterACT must authenticate any endpoint used for network management before establishing a local, remote, and/or network connection using cryptographically based bidirectional authentication.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication. Use of non-secure versions of management protocols with well-known exploits puts the system at immediate risk.'
  desc 'check', 'Review the CounterACT configuration to determine if the network device authenticates network management endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "CLI" tab.
3. If the radio button for "Use CLI" is selected, verify that the "SSH" drop-down option is also selected. Repeat this process for each switch.

If anything other than SSH is selected, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate network management endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "CLI" tab.
3. If the radio button for "Use CLI" is selected, select the "SSH" drop-down option and use proper credentials.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76245'
  tag rid: 'SV-90933r1_rule'
  tag stig_id: 'CACT-NM-000039'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-82881r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

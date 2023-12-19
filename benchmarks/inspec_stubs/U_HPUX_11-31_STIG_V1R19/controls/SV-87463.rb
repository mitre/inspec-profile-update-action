control 'SV-87463' do
  title 'Wireless network adapters must be disabled.'
  desc 'The use of wireless networking can introduce many different attack vectors into the organization’s network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.'
  desc 'check', 'This is N/A for systems that do not have wireless network adapters.

Verify that there are no wireless interfaces configured on the system:

# nwmgr

Note: This command will produce a list of interfaces that are configured on the host.

With the assistance of the System Administrator, identify any wireless interfaces listed in the output of the above command.

If a wireless interface is configured, it must be documented and approved by the local Authorizing Official.

If a wireless interface is configured and has not been documented and approved, this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-72935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72819'
  tag rid: 'SV-87463r1_rule'
  tag stig_id: 'GEN007841'
  tag gtitle: 'GEN007841'
  tag fix_id: 'F-79241r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
end

control 'SV-250607' do
  title 'Wireless network adapters must be disabled.'
  desc "The use of wireless networking can introduce many different attack vectors into the organization's network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service  to valid network resources.

"
  desc 'check', 'This is N/A for systems that do not have wireless network adapters.

If a wireless interface is configured, it must be documented and approved by the local Authorizing Official.

If a wireless interface is configured and has not been documented and approved, this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54042r798818_chk'
  tag severity: 'medium'
  tag gid: 'V-250607'
  tag rid: 'SV-250607r798820_rule'
  tag stig_id: 'GEN007841-ESXI5-000120'
  tag gtitle: 'SRG-OS-000300-VMM-001070'
  tag fix_id: 'F-53996r798819_fix'
  tag satisfies: ['SRG-OS-000300-VMM-001070', 'SRG-OS-000299-VMM-001060', 'SRG-OS-000423-VMM-001700', 'SRG-OS-000481-VMM-002010']
  tag 'documentable'
  tag legacy: ['V-73127', 'SV-87779']
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
end

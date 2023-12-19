control 'SV-216136' do
  title 'The system must not respond to multicast echo requests.'
  desc 'Multicast echo requests can be useful for reconnaissance of systems and for denial of service attacks.'
  desc 'check', 'Determine if response to multicast echo requests is disabled.

# ipadm show-prop -p _respond_to_echo_multicast -co current ipv4
# ipadm show-prop -p _respond_to_echo_multicast -co current ipv6


If the output of all commands is not "0", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable respond to echo multi-cast for IPv4 and IPv6.

# pfexec ipadm set-prop -p _respond_to_echo_multicast=0 ipv4
# pfexec ipadm set-prop -p _respond_to_echo_multicast=0 ipv6'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17374r372790_chk'
  tag severity: 'low'
  tag gid: 'V-216136'
  tag rid: 'SV-216136r603268_rule'
  tag stig_id: 'SOL-11.1-050060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17372r372791_fix'
  tag 'documentable'
  tag legacy: ['V-48185', 'SV-61057']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-216138' do
  title 'The system must set strict multihoming.'
  desc 'These settings control whether a packet arriving on a non-forwarding interface can be accepted for an IP address that is not explicitly configured on that interface.

This rule is NA for documented systems that have interfaces that cross strict networking domains (for example, a firewall, a router, or a VPN node).'
  desc 'check', 'Determine if strict multihoming is configured.

# ipadm show-prop -p _strict_dst_multihoming -co current ipv4
# ipadm show-prop -p _strict_dst_multihoming -co current ipv6

If the output of all commands is not "1", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable strict multihoming for IPv4 and IPv6.

# pfexec ipadm set-prop -p _strict_dst_multihoming=1 ipv4
# pfexec ipadm set-prop -p _strict_dst_multihoming=1 ipv6'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17376r372796_chk'
  tag severity: 'medium'
  tag gid: 'V-216138'
  tag rid: 'SV-216138r603268_rule'
  tag stig_id: 'SOL-11.1-050080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17374r372797_fix'
  tag 'documentable'
  tag legacy: ['V-48193', 'SV-61065']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

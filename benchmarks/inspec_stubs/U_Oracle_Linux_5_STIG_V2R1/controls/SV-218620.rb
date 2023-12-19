control 'SV-218620' do
  title 'The system must be configured with a default gateway for IPv6 if the system uses IPv6, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check for a default route for IPv6. If the system is a VM host and acts as a router solely for the benefit of its client systems, then this rule is not applicable.

# ip -6 route list | grep default

If the system uses IPv6, and no results are returned, this is a finding.'
  desc 'fix', 'Add a default route for IPv6.

Edit /etc/sysconfig/network-scripts/ifcfg-eth0 (substitute interface as appropriate).

Add an IPV6_DEFAULTGW=<gateway> configuration setting.
Restart the interface.

# ifdown eth0; ifup eth0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20095r556058_chk'
  tag severity: 'medium'
  tag gid: 'V-218620'
  tag rid: 'SV-218620r603259_rule'
  tag stig_id: 'GEN005570'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20093r556059_fix'
  tag 'documentable'
  tag legacy: ['V-22490', 'SV-64107']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

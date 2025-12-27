control 'SV-46111' do
  title 'The system must be configured with a default gateway for IPv6 if the system uses IPv6, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check for a default route for IPv6. If the system is a VM host and acts as a router solely for the benefit of its client systems, then this rule is not applicable.

# ip -6 route list | grep default
If the system uses IPv6, and no results are returned, this is a finding.'
  desc 'fix', 'Add a default route for IPv6.
Edit /etc/sysconfig/network/routes
Restart the interface.
# ifdown eth0; ifup eth0'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43368r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22490'
  tag rid: 'SV-46111r1_rule'
  tag stig_id: 'GEN005570'
  tag gtitle: 'GEN005570'
  tag fix_id: 'F-39452r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

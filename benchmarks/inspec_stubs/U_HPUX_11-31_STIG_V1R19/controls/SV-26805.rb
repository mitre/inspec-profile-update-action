control 'SV-26805' do
  title 'The system must be configured with a default gateway for IPv6 if the system uses IPv6, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check for a default route for IPv6:
# netstat -f inet6 -r | grep default
If the system uses IPv6 and no results are returned, this is a finding.'
  desc 'fix', 'Add a default route for IPv6.
Edit /etc/rc.config.d/netconf-ipv6 
Add an IPV6_GATEWAY[0]="<gateway>"
Restart the system to apply the new default gateway setting.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-27794r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22490'
  tag rid: 'SV-26805r1_rule'
  tag stig_id: 'GEN005570'
  tag gtitle: 'GEN005570'
  tag fix_id: 'F-24050r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

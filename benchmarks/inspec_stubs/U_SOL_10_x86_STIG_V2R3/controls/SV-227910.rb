control 'SV-227910' do
  title 'The system must be configured with a default gateway for IPv6 if the system uses IPv6, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check for a default route for IPv6.
# netstat -f inet6 -r | grep default
If the system uses IPv6, and no results are returned, this is a finding.'
  desc 'fix', 'Add a default route for IPv6.
# route add -inet6 default <gateway>
Add this command to an init script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30072r490135_chk'
  tag severity: 'medium'
  tag gid: 'V-227910'
  tag rid: 'SV-227910r603266_rule'
  tag stig_id: 'GEN005570'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30060r490136_fix'
  tag 'documentable'
  tag legacy: ['V-22490', 'SV-26804']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

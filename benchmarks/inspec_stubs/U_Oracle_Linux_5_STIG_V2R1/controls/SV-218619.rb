control 'SV-218619' do
  title 'The system must be configured with a default gateway for IPv4 if the system uses IPv4, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check the system for an IPv4 default route. If the system is a VM host and acts as a router solely for the benefit of its client systems, then this rule is not applicable.

Procedure:
# netstat -r |grep default

If a default route is not defined, this is a finding.'
  desc 'fix', 'Set a default gateway for IPv4.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20094r556055_chk'
  tag severity: 'medium'
  tag gid: 'V-218619'
  tag rid: 'SV-218619r603259_rule'
  tag stig_id: 'GEN005560'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20092r556056_fix'
  tag 'documentable'
  tag legacy: ['V-4397', 'SV-64105']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

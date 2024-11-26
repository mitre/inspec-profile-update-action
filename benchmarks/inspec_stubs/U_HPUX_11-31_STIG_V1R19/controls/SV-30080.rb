control 'SV-30080' do
  title 'The system must be configured with a default gateway for IPv4 if the system uses IPv4, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check the system for an IPv4 default route.
# netstat -r |grep default

If a default route is not defined, this is a finding.'
  desc 'fix', 'Edit /etc/rc.config.d/netconf and add configuration for a default route. For a default gateway of 192.168.3.1:

ROUTE_DESTINATION[0]=default
ROUTE_MASK[0]=""
ROUTE_GATEWAY[0]=192.168.3.1
ROUTE_COUNT[0]=1
ROUTE_ARGS[0]=""

Restart the system for the setting to take effect.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36669r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4397'
  tag rid: 'SV-30080r1_rule'
  tag stig_id: 'GEN005560'
  tag gtitle: 'GEN005560'
  tag fix_id: 'F-32042r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

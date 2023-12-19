control 'SV-4397' do
  title 'The system must be configured with a default gateway for IPv4 if the system uses IPv4, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial-of-Service attacks.'
  desc 'check', 'Check the system for an IPv4 default route.

Procedure:
# netstat -r |grep default

If a default route is not defined, this is a finding.'
  desc 'fix', 'Set  a default gateway for IPv4.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8275r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4397'
  tag rid: 'SV-4397r2_rule'
  tag stig_id: 'GEN005560'
  tag gtitle: 'GEN005560'
  tag fix_id: 'F-4308r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-227909' do
  title 'The system must be configured with a default gateway for IPv4 if the system uses IPv4, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check the system for an IPv4 default route.

Procedure:
# netstat -r |grep default

If a default route is not defined, this is a finding.'
  desc 'fix', 'Create or edit /etc/defaultrouter to contain the default gateway address.

Procedure (for a default gateway of 192.168.3.1):
# echo "192.168.3.1" > /etc/defaultrouter

Restart the system for the setting to take effect.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30071r490132_chk'
  tag severity: 'medium'
  tag gid: 'V-227909'
  tag rid: 'SV-227909r603266_rule'
  tag stig_id: 'GEN005560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30059r490133_fix'
  tag 'documentable'
  tag legacy: ['V-4397', 'SV-30079']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

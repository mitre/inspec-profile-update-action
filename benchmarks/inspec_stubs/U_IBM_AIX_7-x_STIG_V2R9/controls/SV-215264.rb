control 'SV-215264' do
  title 'AIX must be configured with a default gateway for IPv6 if the system uses IPv6 unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'If the system is a router, this is Not Applicable. 

If the system does not use IPv6, this is Not Applicable. 

Determine if the system has a default route configured for IPv6 by running: 

# netstat -r | grep default 
default            10.11.20.1       UG        1      1823 en0      -      -

If a default route is not defined, this is a finding.'
  desc 'fix', 'Configure an IPv6 default route on the system: 
# smitty route'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16462r294243_chk'
  tag severity: 'medium'
  tag gid: 'V-215264'
  tag rid: 'SV-215264r508663_rule'
  tag stig_id: 'AIX7-00-002065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16460r294244_fix'
  tag 'documentable'
  tag legacy: ['SV-101805', 'V-91707']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

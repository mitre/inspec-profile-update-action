control 'SV-26165' do
  title 'The system must be configured with a default gateway for IPv6 if the system uses IPv6, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial-of-Service attacks.'
  desc 'check', 'If the system is a router, this is not applicable.
If the system does not use IPv6, this is not applicable.
Determine if the system has a default route configured for IPv6.  If it does not, this is a finding.'
  desc 'fix', 'Configure an IPv6 default route on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29272r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22490'
  tag rid: 'SV-26165r1_rule'
  tag stig_id: 'GEN005570'
  tag gtitle: 'GEN005570'
  tag fix_id: 'F-26299r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

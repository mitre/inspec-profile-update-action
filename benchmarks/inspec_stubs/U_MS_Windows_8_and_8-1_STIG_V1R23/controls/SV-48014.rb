control 'SV-48014' do
  title 'Systems must be physically secured.'
  desc 'Inadequate physical protection can undermine all other security precautions utilized to protect the system. This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security is the first line of protection of any system.'
  desc 'check', 'Verify user workstations containing sensitive data are in access-controlled areas.  Users must maintain control of, and protect, mobile systems.  If systems are not adequately protected, this is a finding.'
  desc 'fix', 'Establish site policy that ensures workstations containing sensitive data are located inside a controlled access area.   Establish a policy on protecting mobile systems outside of controlled areas.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44752r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1070'
  tag rid: 'SV-48014r1_rule'
  tag stig_id: 'WN08-00-000001'
  tag gtitle: 'Physical security'
  tag fix_id: 'F-41152r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

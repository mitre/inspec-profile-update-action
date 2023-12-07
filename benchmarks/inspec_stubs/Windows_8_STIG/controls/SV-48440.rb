control 'SV-48440' do
  title 'Built-in cameras must be disabled unless allowed by physical security policies.'
  desc 'Cameras can capture still pictures and video of sensitive information.  There is also a potential for remote access, and cameras must be turned off unless approved by local policy.'
  desc 'check', 'Verify built-in cameras are turned off unless allowed by physical security policies.  View status in device manager.
If cameras have not been disabled per physical security policies, this is a finding.

If the system does not have cameras, this is not applicable.'
  desc 'fix', 'Disable built-in cameras in device manager unless allowed by physical security policies.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36763'
  tag rid: 'SV-48440r2_rule'
  tag stig_id: 'WN08-MO-000009'
  tag gtitle: 'WN08-MO-000009'
  tag fix_id: 'F-41568r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

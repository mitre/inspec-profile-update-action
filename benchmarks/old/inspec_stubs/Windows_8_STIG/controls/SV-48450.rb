control 'SV-48450' do
  title 'Global Positioning System (GPS) must be disabled unless required and approved by the organization.'
  desc 'GPS may provide sensitive location information through various applications and embedded meta-data.'
  desc 'check', 'Verify GPS is turned off unless approved by the organization.   View status in device manager or GPS management application.
If GPS is not approved or disabled, this is a finding.

If the system does not have GPS, this is not applicable.'
  desc 'fix', 'Disable GPS in device manager if not organizationally approved.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36767'
  tag rid: 'SV-48450r2_rule'
  tag stig_id: 'WN08-MO-000011'
  tag gtitle: 'WN08-MO-000011'
  tag fix_id: 'F-41578r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-108023' do
  title 'Only authorized versions of BlackBerry OS must be used.'
  desc 'BlackBerry OS is no longer supported by BlackBerry and therefore, may contain security vulnerabilities. BlackBerry OS is not authorized within the DoD.'
  desc 'check', 'Interview ISSO and site mobile device system administrator.

Verify the site is not using the BlackBerry OS on any site mobile devices.

If the site is using BlackBerry OS on any site mobile devices, this is a finding.'
  desc 'fix', 'Remove all BlackBerry OS mobile devices from the site and off the Mobile Device Manager (MDM) server.'
  impact 0.7
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-97755r1_chk'
  tag severity: 'high'
  tag gid: 'V-98919'
  tag rid: 'SV-108023r1_rule'
  tag stig_id: 'BB10-3X-999999'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-104595r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

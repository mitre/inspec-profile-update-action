control 'SV-222659' do
  title 'The application must be decommissioned when maintenance or support is no longer available.'
  desc 'Unsupported software products should not be used because fixes to newly identified bugs will not be implemented by the vendor or development team. The lack of security updates can result in potential vulnerabilities.

When maintenance updates and patches are no longer available, the application is no longer considered supported, and should be decommissioned.'
  desc 'check', 'Interview the application representative and determine if all the application components are under maintenance contract. The entire application may be covered by a single maintenance agreement. The application should be decommissioned if maintenance or security support is no longer being provided by the vendor or by the development staff of a custom developed application.

If the application or any of the application components are not being maintained, this is a finding.'
  desc 'fix', 'Ensure there is maintenance for the application.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24329r493885_chk'
  tag severity: 'high'
  tag gid: 'V-222659'
  tag rid: 'SV-222659r879887_rule'
  tag stig_id: 'APSC-DV-003250'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24318r493886_fix'
  tag 'documentable'
  tag legacy: ['SV-85019', 'V-70397']
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']
end

control 'SV-222652' do
  title 'Security flaws must be fixed or addressed in the project plan.'
  desc 'This requirement is meant to apply to developers or organizations that are doing application development work.

Application development efforts include the creation of a project plan to track and organize the development work.

If security flaws are not tracked within the project plan, it is possible the flaws will be overlooked and included in a release.

Tracking flaws in the project plan will help identify code elements to be changed as well as the requested change.'
  desc 'check', 'This requirement is meant to apply to developers or organizations that are doing application development work. If the organization managing the application is not performing or managing the development of the application the requirement is not applicable.

Ask the application representative to demonstrate how security flaws are integrated into the project plan.

If security flaws are not addressed in the project plan or there is no process to introduce security flaws into the project plan, this is a finding.'
  desc 'fix', 'Address security flaws within a project plan to ensure they are tracked and addressed by management.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24322r493864_chk'
  tag severity: 'medium'
  tag gid: 'V-222652'
  tag rid: 'SV-222652r879887_rule'
  tag stig_id: 'APSC-DV-003210'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24311r493865_fix'
  tag 'documentable'
  tag legacy: ['SV-85005', 'V-70383']
  tag cci: ['CCI-003178']
  tag nist: ['SA-11 e']
end

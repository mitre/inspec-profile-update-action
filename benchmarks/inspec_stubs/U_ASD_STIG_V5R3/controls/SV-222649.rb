control 'SV-222649' do
  title 'Code coverage statistics must be maintained for each release of the application.'
  desc 'This requirement is meant to apply to developers or organizations that are doing application development work.

Code coverage statistics describes the overall functionality provided by the application and how much of the source code has been tested during the release cycle.

To avoid the potential for testing the same pieces of code over and over again, code coverage statistics are used to track which aspects or modules of the application are tested.

Some applications are so large that it is not feasible to test every last bit of the application code on one release cycle. In those instances, it is acceptable to prioritize and identify the modules that are critical to the applications security posture and test those first. Rolling over to test other modules later as resources permit. E.g., testing functionality that performs authentication and authorization before testing printing capabilities.

Application developers should keep statistics that show all of the modules of the application and identify which modules were tested and when. This will help testers to keep track of what has been tested and help to verify all functionality is tested.

The developer makes sure that flaws are documented in a defect tracking system.

If the application is smaller in nature and all aspects of the application can be tested, the code coverage statistics would be 100%.'
  desc 'check', 'If the organization does not do or manage the application development work for the application, this requirement is not applicable.

Ask the application representative to provide code coverage statistics maintained for the application.

If these code coverage statistics do not exist, this is a finding.'
  desc 'fix', 'Track application testing and maintain statistics that show how much of the application function was tested.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24319r493855_chk'
  tag severity: 'low'
  tag gid: 'V-222649'
  tag rid: 'SV-222649r879887_rule'
  tag stig_id: 'APSC-DV-003180'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24308r493856_fix'
  tag 'documentable'
  tag legacy: ['SV-84999', 'V-70377']
  tag cci: ['CCI-003188']
  tag nist: ['SA-11 (4)']
end

control 'SV-234032' do
  title 'Tanium must implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.'
  desc 'Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the system. Changes to information system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the application. Examples of security responses include, but are not limited to the following: halting application processing; halting selected application functions; or issuing alerts/notifications to organizational personnel when there is an unauthorized modification of a configuration item.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on the module "Integrity Monitor".

Click on "Monitors" from the left menu.

Ensure "Monitors" are deployed with applicable Watchlists and Endpoints.

Record any that have a number greater than "0" otherwise, this is a finding.

If using third party integrity monitoring tools, this is Not Applicable.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on the module "Integrity Monitor".

Click "Watchlist" from the left menu.

 "Create a New Watchlist" in the upper right corner.

Add Name and Description of the new Watchlist.

Select "Path Style" that fits your enterprise needs.

Select "Create".

Click on the new Watchlist.

Select "Add Paths".

Add paths to be monitored (Work with your TAM to determine correct paths).

Click "Monitor" from the left menu.
 
 "Create a New Monitor" in the upper right corner.

Add "Name"

Add "Description".

Add computers for the new Monitor along with Watchlist.

Click "Create".

Select "Deploy Monitors".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37217r610596_chk'
  tag severity: 'medium'
  tag gid: 'V-234032'
  tag rid: 'SV-234032r612749_rule'
  tag stig_id: 'TANS-00-000655'
  tag gtitle: 'SRG-APP-000379'
  tag fix_id: 'F-37182r610597_fix'
  tag 'documentable'
  tag legacy: ['SV-102137', 'V-92035']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end

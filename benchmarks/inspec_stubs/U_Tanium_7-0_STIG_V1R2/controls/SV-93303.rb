control 'SV-93303' do
  title 'Tanium must restrict the ability of individuals to place too much impact upon the network, which might result in a denial-of-service (DoS) event on the network by using RandomSensorDelayInSeconds.'
  desc 'DoS is a condition where a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Individuals of concern can include hostile insiders or external adversaries that have successfully breached the information system and are using the system as a platform to launch cyber attacks on third parties.

Applications and application developers must take the steps needed to ensure users cannot use an authorized application to launch DoS attacks against other systems and networks. For example, applications may include mechanisms that throttle network traffic so users are not able to generate unlimited network traffic via the application. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks.

The methods employed to counter this risk will be dependent upon the application layer methods that can be used to exploit it.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box type "RandomSensorDelayInSeconds".

Click "Enter".

If no results are returned, this is a finding.

If results are returned for "RandomSensorDelayInSeconds", but do not match the defined value in the system documentation, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog box, enter "RandomSensorDelayInSeconds" for "Setting Name:".

Consult with a Tanium TAM for an appropriate value for a given network.

Enter the value for "Setting Value:".

Select "Clients" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".

Document the value for later use.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78597'
  tag rid: 'SV-93303r1_rule'
  tag stig_id: 'TANS-CL-000013'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-85333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end

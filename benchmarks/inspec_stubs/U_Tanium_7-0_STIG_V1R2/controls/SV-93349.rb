control 'SV-93349' do
  title 'Tanium must provide the capability to centrally review and analyze audit records from multiple components within the system.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Tanium Sources listed.

If an "Audit Log" Source does not exist, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "Create Connection".

In the Source and Destination section, select "Audit Log" as the Source from the drop-down menu.

In the Destination section, select the desired Destination and fill in the respective fields.

In the Format section, select the desired file format type.

In the Schedule section, select the desired schedule.

Click "Create Connection".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78213r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78643'
  tag rid: 'SV-93349r1_rule'
  tag stig_id: 'TANS-CN-000037'
  tag gtitle: 'SRG-APP-000111'
  tag fix_id: 'F-85379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end

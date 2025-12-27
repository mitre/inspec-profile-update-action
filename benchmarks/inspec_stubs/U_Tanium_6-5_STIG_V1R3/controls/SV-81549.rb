control 'SV-81549' do
  title 'The Tanium Application Server console must be configured to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the application. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The application must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI).

If a DoD-approved use notification banner does not display prior to logon, this is a finding.'
  desc 'fix', 'Create an .html file composed of the DoD-authorized warning banner verbiage. Name the file “warning_banner.html”.

Copy the .html file to the Tanium Server’s http folder.

Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

Click on "+ Add New Setting".

In "Create New Setting" dialog box, enter "console_PreLoginBannerHTML" for "Setting Name:".

Enter “warning_banner.html” for “Setting Value:”.

Enter Text for “Value Type:”.

Enter Server for “Affects:”. 

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67059'
  tag rid: 'SV-81549r1_rule'
  tag stig_id: 'TANS-SV-000042'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-73159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end

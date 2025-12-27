control 'SV-81485' do
  title 'The Tanium Console_ProhibitSavedLogin option must be explicitly enabled to prevent console browsers from saving non-CAC logon information.'
  desc "The Tanium Console, by default, can cache console users' credentials for convenience so that operators are not required to re-enter their passwords when logging back into the console. When this feature is enabled, there is a risk of access by individuals other than the original console user. Depending upon the original console user's privileges, such access could result in irreversible or malicious manipulation of the Tanium configuration.

Although this option is not an impact when CAC is enabled, this feature should be explicitly disabled in the event CAC authentication is ever broken or removed."
  desc 'check', 'Using a web browser on a system which has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and logon with CAC.

Click on "Administration".

Select the "Global Settings" tab.

In the search box beside "Show Settings Containing:" type "console_prohibitSavedLogin".  Enter.

If no results are returned, this is a finding.

If results are returned for "console_prohibitSavedLogin", but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system which has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and logon with CAC.

Click on "Administration".

Select the "Global Settings" tab.

Click on "+ Add New Setting".

In "Create New Setting" dialog box  enter "console_prohibitSavedLogin" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Numeric" from "Value Type" drop-down list.

Select "Server" from "Affects drop-down list.

Click Save.'
  impact 0.7
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67631r1_chk'
  tag severity: 'high'
  tag gid: 'V-66995'
  tag rid: 'SV-81485r1_rule'
  tag stig_id: 'TANS-CN-000001'
  tag gtitle: 'SRG-APP-000002'
  tag fix_id: 'F-73095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end

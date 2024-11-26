control 'SV-234058' do
  title 'The publicly accessible Tanium application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.'
  desc %q(Display of a standardized and approved use notification before granting access to the publicly accessible application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for desktops, laptops, and other devices accommodating banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."

)
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

If a DoD-approved use notification banner does not display prior to logon, this is a finding.'
  desc 'fix', 'Create an .html file composed of the DoD-authorized warning banner verbiage.

Name the file "warning_banner.html".

Copy the .html file to the Tanium Server’s http folder.

Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog box, enter "console_PreLoginBannerHTML" for "Setting Name:".

Enter "warning_banner.html" for "Setting Value:".

Enter Server for "Affects:".

Enter Text for "Value Type:".

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37243r610674_chk'
  tag severity: 'medium'
  tag gid: 'V-234058'
  tag rid: 'SV-234058r612749_rule'
  tag stig_id: 'TANS-CN-000015'
  tag gtitle: 'SRG-APP-000070'
  tag fix_id: 'F-37208r610675_fix'
  tag satisfies: ['SRG-APP-000070', 'SRG-APP-000068', 'SRG-APP-000069']
  tag 'documentable'
  tag legacy: ['SV-102189', 'V-92087']
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388', 'CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3', 'AC-8 a', 'AC-8 b']
end

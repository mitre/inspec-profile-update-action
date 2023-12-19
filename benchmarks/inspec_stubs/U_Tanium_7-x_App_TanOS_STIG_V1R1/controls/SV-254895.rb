control 'SV-254895' do
  title 'The publicly accessible Tanium application must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the application.'
  desc 'Display of a standardized and approved use notification before granting access to the publicly accessible application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for desktops, laptops, and other devices accommodating banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Verify DOD use notification displayed prior to login. 
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. At any time, the USG may inspect and seize data stored on this IS. Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If a DOD-approved use notification banner does not display prior to logon, this is a finding.'
  desc 'fix', '1. Create an .html file composed of the DOD-authorized warning banner verbiage.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. At any time, the USG may inspect and seize data stored on this IS. Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

2. Name the file "warning_banner.html".

3. Use SFTP to upload the HTML banner file to the /incoming folder.

4. Access the Tanium Server interactively.
 
5. Log on to the TanOS server with the tanadmin user role.

6. Enter 2: Tanium Operations >> X: Advanced Operations >> 4: Manage HTML Banner and follow the prompts to copy the HTML banner file to the appropriate location.

7. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

8. Click "Administration" on the top navigation banner.

9. Under Configuration, select "Platform Settings.

10. Click "Create Setting".

11. Select "Server" box from "Setting Type".

12. In " Create Platform Setting" dialog box, enter "console_PreLoginBannerHTML" for "Name". 

13. Select "Text" radio button from "Value Type".

14. Enter "warning_banner.html" for "Value:". 

15. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58508r867583_chk'
  tag severity: 'medium'
  tag gid: 'V-254895'
  tag rid: 'SV-254895r867585_rule'
  tag stig_id: 'TANS-AP-000175'
  tag gtitle: 'SRG-APP-000068'
  tag fix_id: 'F-58452r867584_fix'
  tag satisfies: ['SRG-APP-000068', 'SRG-APP-000070']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end

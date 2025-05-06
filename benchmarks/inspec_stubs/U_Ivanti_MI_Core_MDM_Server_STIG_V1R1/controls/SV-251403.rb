control 'SV-251403' do
  title 'The Ivanti MobileIron Core server must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.'
  desc %q(Display of the DoD-approved use notification before granting access to the application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for applications that can accommodate banners of 1300 characters:

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
  desc 'check', 'Review MDM server documentation and configuration settings to determine if the MDM server is using the warning banner and the wording of the banner is the required text.

On the MDM console, do the following:
1. Connect to the MobileIron Core Server using SSH.
2. Type in a user name and press enter.
3. Verify the required banner is displayed before the password prompt. The required text is found in the Vulnerability Discussion.
If the required banner is not presented, this is a finding.

1. Connect to the MobileIron Core Server system manager portal using a web browser.
2. Verify the required banner is displayed on the web page. The required text is found in the Vulnerability Discussion.
If the required banner is not presented, this is a finding.

1. Connect to the MobileIron Core Server administrator portal using a web browser.
2. Verify the required banner is displayed on the web page.
If the required banner is not presented, this is a finding.'
  desc 'fix', 'Configure the MDM server to display the appropriate warning banner text.

On the MDM console, do the following:
1. Log in to the MobileIron Core Server administrator portal as  a user with the security configuration administrator role using a web browser.
2. Select Settings on the web page.
3. Select General on the web page.
4. Select Login on the web page.
5. Check the "Enable Login Text Box" on the web page.
6. Type the required banner text in the "Text to Display" dialog on the web page.
7. Select "Save" on the web page.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54838r806339_chk'
  tag severity: 'medium'
  tag gid: 'V-251403'
  tag rid: 'SV-251403r806341_rule'
  tag stig_id: 'IMIC-11-001500'
  tag gtitle: 'SRG-APP-000068-UEM-000037'
  tag fix_id: 'F-54791r806340_fix'
  tag satisfies: ['FTA_TAB.1.1', 'FMT_SMF.1.1(2) c.2 \nReference: PP-MDM-411056']
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

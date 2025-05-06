control 'SV-225648' do
  title 'The [selection: Samsung SDS EMM, MDM platform] must have the capability to display the DoD warning banner prior to establishing a user session.'
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

SFR ID: FTA_TAB.1.1, FMT_SMF.1.1(2) c.2)
  desc 'check', 'Review Samsung SDS EMM server documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and click "EULA" at the top of the window.
3. Check the required DoD text in the EULA "Content" box.

If the warning banner is not set up on the MDM server or wording does not exactly match the VulDiscussion text, this is a finding.'
  desc 'fix', 'Configure the MDM server to display the appropriate warning banner text.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and click "EULA" on the top of the window.
3. Enter required DoD text in the EULA "Content" box.
4. Click "Save".'
  impact 0.3
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27349r560966_chk'
  tag severity: 'low'
  tag gid: 'V-225648'
  tag rid: 'SV-225648r588007_rule'
  tag stig_id: 'SSDS-00-000670'
  tag gtitle: 'PP-MDM-413002'
  tag fix_id: 'F-27337r560967_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

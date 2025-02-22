control 'SV-224376' do
  title 'The BlackBerry UEM server must be configured to display the required DoD warning banner upon administrator logon. 

Note: This requirement is not applicable if the TOE platform is selected in FTA_TAB.1.1 in the Security Target (ST).'
  desc 'Note: The advisory notice and consent warning message is not required if the general purpose OS or network device displays an advisory notice and consent warning message when the administrator logs on to the general purpose OS or network device prior to accessing the BlackBerry UEM server or BlackBerry UEM server platform.

Before granting access to the system, the BlackBerry UEM server/server platform is required to display the DoD-approved system use notification message or banner that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met.

The approved DoD text must be used as specified in the KS referenced in DoDI 8500.01.

The non-bracketed text below must be used without any changes as the warning banner. 

[A. Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”]

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

SFR ID: FMT_SMF.1.1(2) c.2'
  desc 'check', 'Review the BlackBerry UEM server documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 
On the BlackBerry UEM, do the following:
1. Log in to the BlackBerry UEM console.
2. Select the "Settings" tab on the left pane.
3. Expand the "General" settings tab on the left pane.
4. Select "Login notices" from the menu in the left pane.
5. Verify the checkbox next to "Enable a login notice for the management console" is checked.
6. Verify the console logon notice text exactly matches the VulDiscussion text. 
7. Verify the checkbox next to "Enable a login notice for the self-service console" is checked if the self-service portal is used at the site.
8. Verify the self-service console logon notice text exactly matches the VulDiscussion text. 

Alternately, have the administrator log in to the UEM console to view the warning banner.

If the console notice wording does not exactly match the VulDiscussion text, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM, do the following:
1. Log in to the BlackBerry UEM console.
2. Select the "Settings" tab on the left pane.
3. Expand the "General" settings tab on the left pane.
4. Select "Login notices" from the menu in the left pane.
5. Click the "pencil" icon (upper right corner) to edit the "Login notice".
6. Select the checkbox next to "Enable a login notice for the management console".
7. In the "Enable a login notice for the management console" field, type the DoD banner found in the VulDiscussion.
8. Click "Save". 

If the self-service portal is used in the organization select the checkbox next to "Enable a login notice for the self-service console" before selecting "Save in step 8.'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26053r539028_chk'
  tag severity: 'medium'
  tag gid: 'V-224376'
  tag rid: 'SV-224376r604136_rule'
  tag stig_id: 'BUEM-00-000520'
  tag gtitle: 'PP-MDM-411056'
  tag fix_id: 'F-26041r539029_fix'
  tag 'documentable'
  tag legacy: ['SV-111869', 'V-102907']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

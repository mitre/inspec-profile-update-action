control 'SV-101915' do
  title 'The MobileIron Core v10 server must be configured to display the required DoD warning banner upon administrator logon. Note: This requirement is not applicable if the TOE platform is selected in FTA_TAB.1.1 in the Security Target (ST).'
  desc 'Note: The advisory notice and consent warning message is not required if the general purpose OS or network device displays an advisory notice and consent warning message when the administrator logs on to the general purpose OS or network device prior to accessing the MobileIron Core v10 server or MobileIron Core v10 server platform.

Before granting access to the system, the MobileIron Core v10 server/server platform is required to display the DoD-approved system use notification message or banner that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met.

The approved DoD text must be used as specified in the KS referenced in DoDI 8500.01.

The non-bracketed text below must be used without any changes as the warning banner. 

[A. Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner must be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”]

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

SFR ID: FMT_SMF.1.1(2) d'
  desc 'check', 'Review MDM server documentation and configuration settings to determine if the MDM server is using the warning banner and the wording of the banner is the required text. 

On the MDM console, do the following:
1. Connect to the MobileIron Core Server using SSH.
2. Type in a user name and press "Enter". 
3. Verify the required banner is displayed before the password prompt. The required text is found in the VulDiscussion.

If the required banner is not presented, this is a finding.

1. Connect to the MobileIron Core Server system manager portal using a web browser.
2. Verify the required banner is displayed on the web page. The required text is found in the VulDiscussion.

If the required banner is not presented, this is a finding.

1. Connect to the MobileIron Core Server administrator portal using a web browser.
2. Verify the required banner is displayed on the web page.

If the required banner is not presented, this is a finding.'
  desc 'fix', 'Configure the MDM server to display the appropriate warning banner text.

On the MDM console, do the following:
1. Logon to the MobileIron Core Server administrator portal as a user with the security configuration administrator role using a web browser.
2. Select "Settings" on the web page.
3. Select "General" on the web page.
4. Select "Logon" on the web page.
5. Check the "Enable Logon Text Box" on the web page.
6. Type the required banner text in the "Text to Display" dialog on the web page.
7. Select "Save" on the web page.'
  impact 0.3
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90971r1_chk'
  tag severity: 'low'
  tag gid: 'V-91813'
  tag rid: 'SV-101915r1_rule'
  tag stig_id: 'MICR-10-000550'
  tag gtitle: 'PP-MDM-311056'
  tag fix_id: 'F-98015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

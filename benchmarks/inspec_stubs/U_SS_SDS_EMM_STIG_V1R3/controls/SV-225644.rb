control 'SV-225644' do
  title 'The Samsung SDS EMM must be configured to display the required DoD warning banner upon administrator logon.

Note: This requirement is not applicable if the TOE platform is selected in FTA_TAB.1.1 in the Security Target (ST).'
  desc 'Note: The advisory notice and consent warning message is not required if the general purpose OS or network device displays an advisory notice and consent warning message when the administrator logs on to the general purpose OS or network device prior to accessing the Samsung SDS EMM or Samsung SDS EMM platform.

Before granting access to the system, the Samsung SDS EMM/server platform is required to display the DoD-approved system use notification message or banner that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met.

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
  desc 'check', 'Review Samsung SDS EMM server documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 

On the MDM console, do the following:
1. Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2. Go to Settings >> Admin Console >> Logo Setting.
3. Verify the text in the "Logo/Notification" window that appears. Confirm the text in the Login Notification box is the required DoD banner text.

Alternately, verify the banner is correct during logon to the console.

If the warning banner is not set up on the Samsung SDS EMM or wording does not exactly match the requirement text, this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM to display the appropriate warning banner text.

Install Samsung SDS EMM patch 2.2.5.1 Build 200707.

On the EMM console, do the following:
1. Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2. Go to Settings >> Admin Console >> Logo Setting and click in the text box and type or paste the DoD banner. 
3. Click "Save".'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27345r560956_chk'
  tag severity: 'medium'
  tag gid: 'V-225644'
  tag rid: 'SV-225644r588007_rule'
  tag stig_id: 'SSDS-00-000530'
  tag gtitle: 'PP-MDM-411056'
  tag fix_id: 'F-27333r560957_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

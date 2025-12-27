control 'SV-87853' do
  title 'Before establishing a user session, the Samsung SDS EMM server must display an administrator-specified advisory notice and consent warning message regarding use of the Samsung SDS EMM server.'
  desc "Note: The advisory notice and consent warning message is not required if the General Purpose OS or Network Device displays an advisory notice and consent warning message when the administrator logs on to the General Purpose OS or Network Device prior to accessing the Samsung SDS EMM server or Samsung SDS EMM server platform.

The Samsung SDS EMM server/server platform is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met. 

The approved DoD text must be used as specified in KS referenced in DoDI 8500.01.

The non-bracketed text below must be used without any changes as the warning banner. 

[A. Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”]

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

[B. For Blackberries and other PDAs/PEDs with severe character limitations:]
I've read & consent to terms in IS user agreem't.

SFR ID: FMT_SMF_EXT.1.1(2) Refinement"
  desc 'check', 'Review Samsung SDS EMM server documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 

On the MDM console, do the following:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Settings >> Admin Console >> System and click on the button labeled “Logo / Notification” near the top of the screen.
3) In the “Logo / Notification” window that appears, confirm the text in the Login Notification “Text” is the required DoD banner text.

If the warning banner is not set up on the MDM server or wording does not exactly match the requirement text, this is a finding.'
  desc 'fix', 'Configure the MDM server to display the appropriate warning banner text.

On the MDM console, do the following:
1) Log into the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Settings >> Admin Console >> System and click on the button labeled “Logo / Notification” near the top of the screen.
3) In the “Logo / Notification” window that appears, enter required DoD text in the Login Notification “Text” box.
4) Click "Save".'
  impact 0.3
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73303r1_chk'
  tag severity: 'low'
  tag gid: 'V-73201'
  tag rid: 'SV-87853r1_rule'
  tag stig_id: 'SEMM-15-000010'
  tag gtitle: 'PP-MDM-201100'
  tag fix_id: 'F-79647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

control 'SV-223246' do
  title 'SharePoint must display an approved system use notification message or banner before granting access to the system.'
  desc 'Applications are required to display an approved system use notification message or banner before granting access to the system providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance and stating that:

(i) users are accessing a U.S. Government information system;
(ii) system usage may be monitored, recorded, and subject to audit;
(iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties; and
(iv) the use of the system indicates consent to monitoring and recording.

System use notification messages can be implemented in the form of warning banners displayed when individuals log on to the information system.

System use notification is intended only for information system access including an interactive logon interface with a human user and is not intended to require notification when an interactive interface does not exist.

Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Note: If no unsanctioned information is transferred, and has been documented by the Data Owner, IRM is not required. This requirement is Not Applicable.

Review the SharePoint server configuration to ensure an approved system use notification message or banner is displayed before granting access to the system.
Banner application occurs on a per-Web Application basis:
Obtain a listing of all SharePoint Web applications.
Open a Web browser and navigate to the SharePoint Web application home page.
Verify the authorized DoD warning banner text is displayed on the SharePoint web application home page.
If the authorized DoD warning banner text is not displayed on the first screen of the SharePoint web application, this is a finding.

Note: Supplementary Information: DoD Logon Banner
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'fix', "Configure the SharePoint web application's home page to display the authorized DoD warning banner text on or before the logon page."
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24919r430798_chk'
  tag severity: 'medium'
  tag gid: 'V-223246'
  tag rid: 'SV-223246r612235_rule'
  tag stig_id: 'SP13-00-000045'
  tag gtitle: 'SRG-APP-000068'
  tag fix_id: 'F-24907r430799_fix'
  tag 'documentable'
  tag legacy: ['SV-74379', 'V-59949']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

control 'SV-95947' do
  title 'The WebSphere Application Server management interface must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc 'Application servers are required to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system management interface, providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance that states that: 

(i) users are accessing a U.S. Government information system; 
(ii) system usage may be monitored, recorded, and subject to audit; 
(iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties; and 
(iv) the use of the system indicates consent to monitoring and recording.

System use notification messages can be implemented in the form of warning banners displayed when individuals log on to the information system. 

System use notification is intended only for information system access including an interactive logon interface with a human user, and is not required when an interactive interface does not exist. 

Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'check', 'Point browser to the URL of the WebSphere administration console.

If the Standard Mandatory DoD Notice and Consent Banner is not displayed, this is a finding.'
  desc 'fix', 'Open the file ${WAS_HOME}/properties/login.info.

Follow the instructions in the HTML comment section to create the pre-logon banner.

Enter the Standard DoD Mandatory Notice and Consent banner into the HTML section.

If logged on to the admin console, log out and log back on to validate the changes.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81233'
  tag rid: 'SV-95947r1_rule'
  tag stig_id: 'WBSP-AS-000310'
  tag gtitle: 'SRG-APP-000068-AS-000035'
  tag fix_id: 'F-88013r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

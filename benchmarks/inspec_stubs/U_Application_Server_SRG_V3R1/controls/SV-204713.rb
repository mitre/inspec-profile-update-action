control 'SV-204713' do
  title 'The application server management interface must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
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
  desc 'check', 'Review the application server management interface configuration to verify the application server is configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access.

The banner must read:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the application server management interface does not display the banner or displays an unapproved banner, this is a finding.'
  desc 'fix', 'Configure the application server management interface so it displays the Standard Mandatory DoD Notice and Consent Banner prior to allowing access.

The banner must read:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4833r282786_chk'
  tag severity: 'medium'
  tag gid: 'V-204713'
  tag rid: 'SV-204713r508029_rule'
  tag stig_id: 'SRG-APP-000068-AS-000035'
  tag gtitle: 'SRG-APP-000068'
  tag fix_id: 'F-4833r282787_fix'
  tag 'documentable'
  tag legacy: ['V-35096', 'SV-46383']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

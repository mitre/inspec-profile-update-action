control 'SV-254102' do
  title 'Nutanix AOS must display the standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc 'Application servers are required to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system management interface, providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance that states that: 

(i) Users are accessing a U.S. Government information system; 
(ii) System usage may be monitored, recorded, and subject to audit; 
(iii) Unauthorized use of the system is prohibited and subject to criminal and civil penalties; and 
(iv) The use of the system indicates consent to monitoring and recording.

System use notification messages can be implemented in the form of warning banners displayed when individuals log on to the information system. 

System use notification is intended only for information system access including an interactive logon interface with a human user, and is not required when an interactive interface does not exist. 

Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

'
  desc 'check', 'Validate that the Prism WebUI "Welcome Banner" is enabled.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the "Welcome Banner".
4. Verify the "Enable Banner" box is selected.

If the "Enable Banner" box is not checked, this is a finding.

Confirm Nutanix AOS Prism WebUI is set to display the Standard Mandatory DoD Notice and Consent Banner.

1.  Log in to Prism Element.
2.  Click on the gear icon in the upper right.
3.  Navigate to the "Welcome Banner".

If the Welcome Banner is not configured with the Standard Mandatory DoD Notice and Consent Banner, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements WebUI to display the Standard Mandatory DoD Notice and Consent Banner.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the "Welcome Banner".
4. Set the Welcome Banner to be configured with the Standardized DoD Use Notification.
5. Check "Enable Banner".
6. Click "Save".'
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57587r846392_chk'
  tag severity: 'low'
  tag gid: 'V-254102'
  tag rid: 'SV-254102r846394_rule'
  tag stig_id: 'NUTX-AP-000080'
  tag gtitle: 'SRG-APP-000068-AS-000035'
  tag fix_id: 'F-57538r846393_fix'
  tag satisfies: ['SRG-APP-000068-AS-000035', 'SRG-APP-000069-AS-000036']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end

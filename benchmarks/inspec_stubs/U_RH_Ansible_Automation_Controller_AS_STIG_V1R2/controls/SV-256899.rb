control 'SV-256899' do
  title 'The Automation Controller management interface must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system.'
  desc 'Automation Controller is required to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system management interface, providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance that states that:

(i) users are accessing a U.S. Government information system; 
(ii) system usage may be monitored, recorded, and subject to audit; 
(iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties; and 
(iv) the use of the system indicates consent to monitoring and recording.

System use notification messages can be implemented in the form of warning banners displayed when individuals log on to the information system.

System use notification is intended only for information system access including an interactive logon interface with a human user, and is not required when an interactive interface does not exist.

Automation Controller supports displaying the Standard Mandatory DOD Notice and Consent Banner prior to logging in via the web console.

'
  desc 'check', 'Navigate to the Automation Controller login page.

Verify that the Standard Mandatory DOD Notice and Consent Banner is displayed with the following text:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the required DOD banner is not displayed on the login page or the CUSTOM_LOGIN_INFO does not contain the correct text, this is a finding.

Alternatively, verify the setting CUSTOM_LOGIN_INFO setting in the REST API at /api/v2/settings/ui by running the following command:

curl https://<Automation Controller HOST>/api/v2/settings/ui'
  desc 'fix', 'Navigate to the Automation Controller web administrator console: 

Settings >> System >> User Interface settings.

Click "Edit".

In the Custom Login Info field, set the following text:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60574r902265_chk'
  tag severity: 'medium'
  tag gid: 'V-256899'
  tag rid: 'SV-256899r903511_rule'
  tag stig_id: 'APAS-AT-000015'
  tag gtitle: 'SRG-APP-000068-AS-000035'
  tag fix_id: 'F-60516r903511_fix'
  tag satisfies: ['SRG-APP-000068-AS-000035', 'SRG-APP-000069-AS-000036']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end

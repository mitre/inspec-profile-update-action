control 'SV-77355' do
  title 'Riverbed Optimization System (RiOS) must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Verify that RiOS is configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Announcements

Verify that the Standard Mandatory DoD Notice and Consent Banner is contained in the Logon Message

If the Standard Mandatory DoD Notice and Consent Banner does not exist on this page, this is a finding.'
  desc 'fix', 'Configure RiOS to display the Standard Mandatory DoD Notice and Consent Banner.

Navigate to the Device Management Console
Navigate to Configure >> System Settings >> Announcement

Cut and past the DoD banner into the Logon Message box:
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

Click "Apply" to save the changes
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63659r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62865'
  tag rid: 'SV-77355r1_rule'
  tag stig_id: 'RICX-DM-000027'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-68783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

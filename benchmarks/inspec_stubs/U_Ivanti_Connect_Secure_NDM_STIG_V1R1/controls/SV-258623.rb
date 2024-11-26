control 'SV-258623' do
  title 'The ICS must be configured to display the Standard Mandatory DOD Notice and Consent Banner before granting access to manage the device.'
  desc 'Display of the DOD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.

The banner is retained until acknowledgement by default when the banner is selected in the sign-in policy.

'
  desc 'check', 'Determine if the network device is configured to present a DOD-approved banner that is formatted in accordance with DTM-08-060.

In the ICS Web UI, navigate to Authentication >> Signing In >> Sign-In Policies/
1. Click the */admin/ (or whatever custom URL is used for CAC/PKI token admin access).
2. Verify the DOD banner is entered exactly as required with no alterations.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details".

If the banner is not used, displayed, or the text/format is altered, this is a finding.'
  desc 'fix', 'Configure ICS to present a DOD-approved banner that is formatted in accordance with DTM-08-060. Do not alter the text or format. Configure */admin/ (or whatever custom URL is used for CAC/PKI token admin access) with a sign-in notice.

In the ICS Web UI, navigate to Authentication >> Signing In >> Sign-In Notifications.
1. Click "New Notification".
2. For name, type: "DOD Notice and Consent".
3. In the text box type the following:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details".
4. Click "Save Changes".
5. Go to Authentication >> Signing In >> Sign-In Policies.
6. Click the */admin/ (or whatever custom URL is used for CAC/PKI token admin access).
7. Under "Configure SignIn Notifications", check the box for "Pre-Auth Sign-in Notification", and in the drop-down menu, assign the notification titled "DOD Notice and Consent".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62363r930555_chk'
  tag severity: 'medium'
  tag gid: 'V-258623'
  tag rid: 'SV-258623r930557_rule'
  tag stig_id: 'IVCS-NM-000710'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-62272r930556_fix'
  tag satisfies: ['SRG-APP-000068-NDM-000215', 'SRG-APP-000069-NDM-000216']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end

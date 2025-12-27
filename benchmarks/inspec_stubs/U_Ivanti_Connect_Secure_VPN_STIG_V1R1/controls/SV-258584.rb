control 'SV-258584' do
  title 'The ICS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to users.'
  desc 'Display of the DOD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

'
  desc 'check', %q(Determine if the network device is configured to present a DOD-approved banner that is formatted in accordance with DTM-08-060. Verify the remote access VPN user access sign-in notice is configured and displayed. This may or may not be the same as the admin portal.

1. In the ICS Web UI, navigate to Authentication >> Signing In >> Sign-In Notifications.

Verify the use of the following verbiage for applications that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details".

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't".

2. In the ICS Web UI, navigate to Authentication >> Signing In >> Sign-In Policies.
3. Click the "*/" (or whatever custom URL is used for remote access VPN user access).

Under "Configure SignIn Notifications", if the "Pre-Auth Sign-in Notification" is not checked, or if the previously mentioned notification text is not assigned to this policy, this is a finding.)
  desc 'fix', 'Configured to present a DOD-approved banner that is formatted in accordance with DTM-08-060. Configure the remote access VPN user access sign-in notice. This may or may not be the same as the admin portal.

In the ICS Web UI, navigate to Authentication >> Signing In >> Sign-In Notifications.
1. Click "New Notification".
2. For name, type: "DOD Notice and Consent".
3. In the text box type the following:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details".
4. Click "Save Changes".
5. Go to Authentication >> Signing In >> Sign-In Policies.
6. Click the "*/" (or whatever custom URL is used for remote access VPN user access).
7. Under "Configure SignIn Notifications", check the box for "Pre-Auth Sign-in Notification" in the drop-down menu, and assign the notification titled "DOD Notice and Consent".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62324r930438_chk'
  tag severity: 'medium'
  tag gid: 'V-258584'
  tag rid: 'SV-258584r930440_rule'
  tag stig_id: 'IVCS-VN-000020'
  tag gtitle: 'SRG-NET-000041-VPN-000110'
  tag fix_id: 'F-62233r930439_fix'
  tag satisfies: ['SRG-NET-000041-VPN-000110', 'SRG-NET-000042-VPN-000120', 'SRG-NET-000043-VPN-000130']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end

control 'SV-207185' do
  title 'The Remote Access VPN Gateway and/or client must display the Standard Mandatory DoD Notice and Consent Banner before granting remote access to the network.'
  desc %q(Display of a standardized and approved use notification before granting access to the network ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

In most VPN implementations, the banner is configured in the management backplane (NDM SRG) and serves as the presentation for the VPN client connection as well as for administrator logon to the device management tool/backplane.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. This requirement applies to VPN gateways that have the concept of a user account and have the logon function residing on the VPN gateway.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for VPN gateways that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'If the user/remote client connection banner is the same as the banner configured as part of the NDM SRG, then this is not applicable.

Determine if the network device is configured to present a DoD-approved banner that is formatted in accordance with DoD policy. 

If the Remote Access VPN Gateway or VPN client does not display the Standard Mandatory DoD Notice and Consent Banner before granting remote access to the network, this is a finding.'
  desc 'fix', %q(Configure the Remote Access VPN to display the Standard Mandatory DoD Notice and Consent Banner in accordance with DoD policy before granting access to the device. Use the following verbiage for applications that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't.")
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7445r378176_chk'
  tag severity: 'medium'
  tag gid: 'V-207185'
  tag rid: 'SV-207185r608988_rule'
  tag stig_id: 'SRG-NET-000041-VPN-000110'
  tag gtitle: 'SRG-NET-000041'
  tag fix_id: 'F-7445r378177_fix'
  tag 'documentable'
  tag legacy: ['V-97043', 'SV-106181']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

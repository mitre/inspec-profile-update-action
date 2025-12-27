control 'SV-207343' do
  title 'The VMM must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc %q(Display of a standardized and approved use notification before granting access to the VMM ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for a VMM that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) VMM (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for VMMs that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', %q(Verify the VMM displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

If it does not, this is a finding.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for a VMM that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) VMM (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for VMMs that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'fix', %q(Configure the VMM to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for a VMM that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) VMM (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for VMMs that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7600r365439_chk'
  tag severity: 'medium'
  tag gid: 'V-207343'
  tag rid: 'SV-207343r378520_rule'
  tag stig_id: 'SRG-OS-000023-VMM-000060'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-7600r365440_fix'
  tag 'documentable'
  tag legacy: ['SV-71099', 'V-56839']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

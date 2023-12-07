control 'SV-257155' do
  title 'The macOS system must display the Standard Mandatory DOD Notice and Consent Banner before granting remote access to the operating system.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060.'
  desc 'check', 'If SSH is not being used, this is not applicable.

Verify the macOS system is configured to display the Standard Mandatory DOD Notice and Consent Banner before granting remote access to the operating system.

Check to see if the operating system has the correct text listed in the "/etc/banner" file with the following command:

/usr/bin/more /etc/banner

The command must return the following text:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the operating system does not display a logon banner before granting remote access or the banner does not match the Standard Mandatory DOD Notice and Consent Banner, this is a finding.

If the text in the "/etc/banner" file does not match the Standard Mandatory DOD Notice and Consent Banner, this is a finding.'
  desc 'fix', 'Configure the macOS system to display the Standard Mandatory DOD Notice and Consent Banner before granting remote access to the operating system by creating a text file containing the required DOD text.

Name the file "banner" and place it in "/etc/".'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60840r905096_chk'
  tag severity: 'medium'
  tag gid: 'V-257155'
  tag rid: 'SV-257155r905098_rule'
  tag stig_id: 'APPL-13-000023'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-60781r905097_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

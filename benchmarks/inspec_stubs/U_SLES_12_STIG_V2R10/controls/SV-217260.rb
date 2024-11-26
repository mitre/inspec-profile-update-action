control 'SV-217260' do
  title 'The SUSE operating system file /etc/gdm/banner must contain the Standard Mandatory DoD Notice and Consent banner text.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the SUSE operating system. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at system logon is required. The system must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Verify the SUSE operating system file "/etc/gdm/banner" contains the Standard Mandatory DoD Notice and Consent Banner text by running the following command:

# more /etc/gdm/banner

If the file does not contain the following text, this is a finding.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'fix', 'Configure the SUSE operating system file "/etc/gdm/banner" to contain the Standard Mandatory DoD Notice and Consent Banner by running the following commands:

# sudo vi /etc/gdm/banner

Add the following information to the file:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18488r369936_chk'
  tag severity: 'medium'
  tag gid: 'V-217260'
  tag rid: 'SV-217260r603262_rule'
  tag stig_id: 'SLES-12-030020'
  tag gtitle: 'SRG-OS-000024-GPOS-00007'
  tag fix_id: 'F-18486r369937_fix'
  tag 'documentable'
  tag legacy: ['V-77433', 'SV-92129']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end

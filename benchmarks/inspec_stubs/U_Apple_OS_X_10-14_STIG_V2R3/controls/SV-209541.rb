control 'SV-209541' do
  title 'The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting GUI access to the system.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060.

'
  desc 'check', 'The policy banner will show if a "PolicyBanner.rtf" or "PolicyBanner.rtfd" exists in the "/Library/Security" folder. Run this command to show the contents of that folder:

/bin/ls -l /Library/Security/PolicyBanner.rtf*

If neither "PolicyBanner.rtf" nor "PolicyBanner.rtfd" exists, this is a finding. 

The banner text of the document MUST read:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the text is not worded exactly this way, this is a finding.'
  desc 'fix', 'Create an RTF file containing the required text. Name the file "PolicyBanner.rtf" or "PolicyBanner.rtfd" and place it in "/Library/Security/".'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9792r282105_chk'
  tag severity: 'medium'
  tag gid: 'V-209541'
  tag rid: 'SV-209541r610285_rule'
  tag stig_id: 'AOSX-14-000025'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-9792r282106_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag legacy: ['V-95821', 'SV-104959']
  tag cci: ['CCI-000050', 'CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 b', 'AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end

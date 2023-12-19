control 'SV-237929' do
  title 'The IBM z/VM TCP/IP must be configured to display the mandatory DoD Notice and Consent banner before granting access to the system.'
  desc %q(Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'Check the TELNET connection exit.

If there is no TELNET connection exit, this is a finding.

If the TELNET connection exit does not send a Notice and Consent message before access is granted, this is a finding.'
  desc 'fix', 'Configure the TELNET connection exit to display a Notice and Consent banner message before access is granted to TELNET.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41139r649625_chk'
  tag severity: 'medium'
  tag gid: 'V-237929'
  tag rid: 'SV-237929r649627_rule'
  tag stig_id: 'IBMZ-VM-000760'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-41098r649626_fix'
  tag 'documentable'
  tag legacy: ['SV-93611', 'V-78905']
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end

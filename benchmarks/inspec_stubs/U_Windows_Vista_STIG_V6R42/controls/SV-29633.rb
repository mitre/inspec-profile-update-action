control 'SV-29633' do
  title 'The required legal notice must be configured to display before console logon.'
  desc 'Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'check', "Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Interactive Logon: Message text for users attempting to log on” is not set to the following, then this is a finding.

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details.

Any OS versions that do not support the full text version must state the following:
“I've read & consent to terms in IS user agreem't.”

Deviations are not permitted except as authorized by the Deputy Assistant Secretary of Defense for Information and Identity Assurance.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  LegalNoticeText

Value Type:  REG_SZ
Value:  See message text above"
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options ->“Interactive Logon: Message text for users attempting to log on” as outlined in the check.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-32717r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1089'
  tag rid: 'SV-29633r3_rule'
  tag gtitle: 'Legal Notice Display'
  tag fix_id: 'F-28804r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end

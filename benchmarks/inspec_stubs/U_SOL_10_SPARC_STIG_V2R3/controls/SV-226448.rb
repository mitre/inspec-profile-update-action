control 'SV-226448' do
  title 'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts.'
  desc 'Failure to display the login banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'check', %q(Access the system console and make a logon attempt. Check for either of the following login banners based on the character limitations imposed by the system. An exact match is required. If one of these banners is not displayed, this is a finding.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. "

OR

"I've read & consent to terms in IS user agreem't.")
  desc 'fix', %q(Edit /etc/issue and add one of the DoD login banners (based on the character limitations imposed by the system).

DoD Login Banners:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR

"I've read & consent to terms in IS user agreem't.")
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36374r602725_chk'
  tag severity: 'medium'
  tag gid: 'V-226448'
  tag rid: 'SV-226448r603265_rule'
  tag stig_id: 'GEN000400'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-36338r602726_fix'
  tag 'documentable'
  tag legacy: ['SV-28596', 'V-763']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

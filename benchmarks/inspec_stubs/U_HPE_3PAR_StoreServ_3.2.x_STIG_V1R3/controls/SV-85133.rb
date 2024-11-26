control 'SV-85133' do
  title 'The Standard Mandatory DoD Notice and Consent Banner must be displayed until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc %q(Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

The banner must be acknowledged by the user prior to allowing the user access to the operating system. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at system logon is required. The system must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."

)
  desc 'check', %q(Verify that the SSH login banner is properly configured.

Enter the following command:

cli% showsshbanner
I've read & consent to terms in IS user agreem't

If the output is not: 

"I've read & consent to terms in IS user agreem't" 

this is a finding.

Alternatively:

To inspect the banner, login via SSH from a remote host. 

If the output shown above is not displayed during SSH authentication, this is a finding.)
  desc 'fix', "To configure the SSH login banner, enter the command:

cli% setsshbanner

Enter the following text:

I've read & consent to terms in IS user agreem't

Then press enter twice to conclude setting the SSH banner text."
  impact 0.3
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70911r1_chk'
  tag severity: 'low'
  tag gid: 'V-70511'
  tag rid: 'SV-85133r1_rule'
  tag stig_id: 'HP3P-32-001600'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-76749r1_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end

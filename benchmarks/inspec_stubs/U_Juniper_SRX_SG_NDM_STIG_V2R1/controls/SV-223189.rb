control 'SV-223189' do
  title 'The Juniper SRX Services Gateway must display the Standard Mandatory DoD Notice and Consent Banner before granting access.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.

The Standard Mandatory DoD Notice and Consent Banner must be displayed before the user has been authenticated.'
  desc 'check', 'Verify the Standard Mandatory DoD Notice and Consent Banner is displayed before the user has been authenticated either locally or by the AAA server by typing the following command at the [edit system login] hierarchy level.

[edit]
show system login message

If the Standard Mandatory DoD Notice and Consent Banner is not displayed before the user has been authenticated, this is a finding.'
  desc 'fix', %q(To configure a system login message, include the message statement at the [edit] hierarchy level.
This is the approved verbiage for applications that can accommodate banners of 1300 characters:

[edit]
set system login message "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\by using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\n\n"

OR

[edit]
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

set system login message "I've read & consent to terms in IS user agreem't>\n\n"

Note: Use \n to insert a line between paragraphs where needed.)
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24862r513260_chk'
  tag severity: 'low'
  tag gid: 'V-223189'
  tag rid: 'SV-223189r513262_rule'
  tag stig_id: 'JUSX-DM-000032'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-24850r513261_fix'
  tag 'documentable'
  tag legacy: ['SV-81045', 'V-66555']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

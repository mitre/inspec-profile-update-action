control 'SV-80649' do
  title 'The HP FlexFabric Switch must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to allowing the administrator access to the HP FlexFabric Switch. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', %q(Determine if the HP FlexFabric Switch is configured to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access. After entering the username and password for HP FlexFabric Switch the banner and acknowledgement of the notice should be displayed:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't."

Press Y or ENTER to continue, N to exit.

If HP FlexFabric Switch does not retain the banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to logon for further access, this is a finding.)
  desc 'fix', 'Configure the HP FlexFabric Switch to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the switch.

[HP]  header legal 
% Desirable text goes here %

Note: In this example, the percentage sign (%) is the starting and ending character of the text argument. Entering the percentage sign after the text quits the header command. Because it is the starting and ending character, the percentage sign is not included in the banner.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66159'
  tag rid: 'SV-80649r1_rule'
  tag stig_id: 'HFFS-ND-000017'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-72235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end

control 'SV-80647' do
  title 'The HP FlexFabric Switch must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the HP FlexFabric Switch ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', %q(Determine if the HP FlexFabric Switch is configured to present a DoD-approved banner that is formatted in accordance with DTM-08-060. Establish a console or vty connection to HP FlexFabric Switch and attempt to logon to it. Once entering the username the banner should appear:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't."

If such a banner is not presented, this is a finding.)
  desc 'fix', 'Configure the HP FlexFabric Switch to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the switch.

[HP]  header legal 
% Desirable text goes here %

Note: In this example, the percentage sign (%) is the starting and ending character of the text argument. Entering the percentage sign after the text quits the header command. Because it is the starting and ending character, the percentage sign is not included in the banner.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66157'
  tag rid: 'SV-80647r1_rule'
  tag stig_id: 'HFFS-ND-000016'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-72233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

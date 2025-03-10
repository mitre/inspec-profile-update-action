control 'SV-77975' do
  title 'The VMM must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'Failure to display the DoD logon banner prior to a log in attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Annotations.WelcomeMessage value and verify it contains the DoD logon banner:

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage

Check for either of the following login banners based on the character limitations imposed by the system. An exact match of the text is required. If one of these banners is not displayed, this is a finding.

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests- -not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

OR

I've read & consent to terms in IS user agreem't.

If the DCUI logon screen does not display the DoD logon banner, this is a finding."
  desc 'fix', 'From a PowerCLI command prompt while connected to the ESXi host copy the following contents into a script(.ps1 file) and run to set the DCUI screen to display the DoD logon banner:

<script begin>

$value = @"
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using this IS (which includes any device attached to this IS), you consent to the following conditions:                 {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  - The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} enforcement (LE), and counterintelligence (CI) investigations.{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  - At any time, the USG may inspect and seize data stored on this IS.{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  - Communications using, or data stored on, this IS are not private, are subject to routine monitoring,            {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} interception, and search, and may be disclosed or used for any USG-authorized purpose.                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  - This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} for your personal benefit or privacy.{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} or monitoring of the content of privileged communications, or work product, related to personal representation  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} product are private and confidential. See User Agreement for details.{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart  {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}{/color}{/bgcolor}
"

@Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value $value

<script end>'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63485'
  tag rid: 'SV-77975r1_rule'
  tag stig_id: 'ESXI-06-100007'
  tag gtitle: 'SRG-OS-000024-VMM-000070'
  tag fix_id: 'F-69415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end

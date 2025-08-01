control 'SV-31259' do
  title 'PDAs/smartphones must display the required banner during device unlock/ logon.'
  desc 'DoD CIO memo requires all PDAs, BlackBerrys, and smartphones to have a consent banner displayed during logon/device unlock to ensure users understand their responsibilities to safeguard DoD data.  When users understand their responsibilities, they are less likely to engage in behaviors that could compromise of DoD information systems.'
  desc 'check', %q(Detailed Policy Requirements:

All PDAs and Smartphones must display the following banner during device unlock/ logon:  
A. Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to
the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest
agreement by clicking on a box indicating "OK."  
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.  By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network
operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

B. For Blackberries and other PDAs/PEDs with severe character limitations:
I've read & consent to terms in IS user agreem't.

Check Procedures:
  
Work with the SA to review the configuration of the PDA security management server or security policy configured on the PDA/smartphone.  Review a sample of devices to check that the required banner is being used.  Mark as a finding if the required banner is not used.

Note:  Depending on the system, this setting could be set on the management server on on the handheld device.)
  desc 'fix', 'Display the required banner during device unlock/logon.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-14398r1_chk'
  tag severity: 'medium'
  tag gid: 'V-25022'
  tag rid: 'SV-31259r1_rule'
  tag stig_id: 'WIR-MOS-PDA-007'
  tag gtitle: 'Required logon banner'
  tag fix_id: 'F-27693r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWM-1'
end

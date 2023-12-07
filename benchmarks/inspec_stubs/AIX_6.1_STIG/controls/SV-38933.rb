control 'SV-38933' do
  title 'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.'
  desc 'Failure to display the login banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.

This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices, as well as, to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'check', %q(Access the graphical desktop environment(s) provided by the system and attempt to logon. Check for either of the following login banners based on the character limitations imposed by the system. An exact match is required. If one of these banners is not displayed, this is a finding.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. "

OR

"I've read & consent to terms in IS user agreem't.")
  desc 'fix', %q(Edit the Xresources file to configure the system to display one of the DoD login banners (based on the character limitations imposed by the system) prior to, or as part of, the graphical desktop environment login process. 

For Dt login, change the variable Dtlogin*greeting.labelString:  in Xresources file.
#cp /usr/dt/config/C/Xresources /etc/dt/config/C/Xresources
#vi /etc/dt/config/C/Xresources

For XDM login, change the variable Xlogin*greeting in the Xresources file.
#vi /usr/lpp/X11/lib/X11/xdm/Xresources.

DoD Login Banners:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. "

OR

"I've read & consent to terms in IS user agreem't.")
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-30811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24331'
  tag rid: 'SV-38933r1_rule'
  tag stig_id: 'GEN000402'
  tag gtitle: 'GEN000402'
  tag fix_id: 'F-31628r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

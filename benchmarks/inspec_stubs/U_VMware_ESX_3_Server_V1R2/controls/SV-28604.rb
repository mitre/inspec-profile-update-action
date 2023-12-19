control 'SV-28604' do
  title 'The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.'
  desc 'Failure to display the login banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.

NOTE: SFTP and FTPS are encrypted alternatives to FTP that should be used in place of FTP. SFTP is implemented by the SSH service and uses its banner configuration.'
  desc 'check', %q(FTP to the system.
# ftp localhost
Check for either of the following login banners based on the character limitations imposed by the system. An exact match is required. If one of these banners is not displayed, this is a finding. If the system does not run the FTP service, this is not applicable.

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
  desc 'fix', "Configure the system to display one of the DoD login banners (based on the character limitations imposed by the system) prior to any FTP login attempt.

DoD Login Banners:

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

OR

I've read & consent to terms in IS user agreem't."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28848r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23732'
  tag rid: 'SV-28604r1_rule'
  tag stig_id: 'GEN000410'
  tag gtitle: 'GEN000410'
  tag fix_id: 'F-25877r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

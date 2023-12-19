control 'SV-250614' do
  title 'The SSH daemon must be configured with the Department of Defense (DoD) logon banner.'
  desc 'Failure to display the DoD logon banner prior to a log in attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'check', %q(Disable lock down mode. Enable the ESXi Shell. Execute the following command to inspect the /etc/issue (or otherwise configured) SSHD banner file:
# cat /etc/issue

Access the system console and make a logon attempt. Check for either of the following login banners based on the character limitations imposed by the system. An exact match is required. 

If one of these banners is not displayed, this is a finding. 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

OR 

"I've read & consent to terms in IS user agreem't."

If the /etc/issue (or otherwise configured) SSHD banner file does not contain one of the two login banners exactly as shown above, this is a finding.

Re-enable lock down mode.)
  desc 'fix', %q(Configure the /etc/issue (or otherwise configured) SSHD banner file in order to display one of the DoD login banners (based on the character limitations imposed by the system) prior to any local login attempt. DoD Login Banners: 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR 

"I've read & consent to terms in IS user agreem't.")
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54049r798839_chk'
  tag severity: 'medium'
  tag gid: 'V-250614'
  tag rid: 'SV-250614r798841_rule'
  tag stig_id: 'SRG-OS-000023-ESXI5'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag fix_id: 'F-54003r798840_fix'
  tag 'documentable'
  tag legacy: ['SV-51252', 'V-39394']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

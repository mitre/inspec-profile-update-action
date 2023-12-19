control 'SV-26802' do
  title 'The SSH daemon must be configured with the Department of Defense (DoD) logon banner.'
  desc 'Failure to display the DoD logon banner prior to a log in attempt will negate legal proceedings resulting from unauthorized access to system resources.

The SSH service must be configured to display the DoD logon warning banner either through the SSH configuration or a wrapper program, such as TCP_WRAPPERS.

The SSH daemon may also be used to provide SFTP service.  The warning banner configuration for SSH will apply to SFTP.'
  desc 'check', %q(Verify the SSH daemon is configured for logon warning banners.
# grep -i banner /etc/ssh/sshd_config | grep -v '^#'
# cat [banner file]
Verify the banner configuration line is present and the file it references contains a logon warning banner.

Check for either of the following login banners based on the character limitations imposed by the system. An exact match is required. If one of these banners is not displayed, this is a finding.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR

"I've read & consent to terms in IS user agreem't."

If the SSH daemon is not configured to display the logon warning banner, this is a finding.)
  desc 'fix', %q(Edit the SSH daemon configuration and add (or edit) a banner setting referencing a file containing a logon warning banner.

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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22489'
  tag rid: 'SV-26802r1_rule'
  tag stig_id: 'GEN005550'
  tag gtitle: 'GEN005550'
  tag fix_id: 'F-24046r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

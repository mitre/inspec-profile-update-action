control 'SV-35152' do
  title 'The SSH daemon must be configured with the Department of Defense (DoD) login banner.'
  desc 'Failure to display the DoD login banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.

The SSH service must be configured to display the DoD logon warning banner either through the SSH configuration or a wrapper program, such as TCP_WRAPPERS.

The SSH daemon may also be used to provide SFTP service.  The warning banner configuration for SSH will apply to SFTP.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=Banner
arg(s)=<Department of Defense (DoD) login banner file name> 

Default values include: <no keyword or banner file name entry>

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "Banner"

Verify the contents of the banner file:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR

"I've read & consent to terms in IS user agreem't."


If configuration information is not returned or the return value does not contain the Department of Defense (DoD) login banner file name (with banner file content verified), this is a finding.)
  desc 'fix', %q(Edit the SSH daemon configuration and add or edit a banner setting referencing a file containing a login warning banner.

If required, edit the sshd banner file and add one of the DoD login banners (based on the character limitations imposed by the system).

DoD Login Banners:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR

"I've read & consent to terms in IS user agreem't")
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35009r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22489'
  tag rid: 'SV-35152r1_rule'
  tag stig_id: 'GEN005550'
  tag gtitle: 'GEN005550'
  tag fix_id: 'F-30303r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

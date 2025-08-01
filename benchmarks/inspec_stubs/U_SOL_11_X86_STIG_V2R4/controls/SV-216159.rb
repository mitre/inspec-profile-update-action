control 'SV-216159' do
  title 'The operating system must display the DoD approved system use notification message or banner for SSH connections.'
  desc 'Warning messages inform users who are attempting to log in to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. As implementing a logon banner to deter inappropriate use can provide a foundation for legal action against abuse, this warning content should be set as appropriate.'
  desc 'check', 'Check SSH configuration for banner message:

# grep "^Banner" /etc/ssh/sshd_config

If the output is not:
Banner /etc/issue
and /etc/issue does not contain the approved banner text, this is a finding.'
  desc 'fix', 'The root role is required.

Edit the SSH configuration file.

# pfedit /etc/ssh/sshd_config

Locate the file containing:

Banner

Change the line to read:

Banner /etc/issue

Edit the /etc/issue file

# pfedit /etc/issue

The DoD required text is:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Restart the SSH service

# svcadm restart svc:/network/ssh'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17397r372859_chk'
  tag severity: 'low'
  tag gid: 'V-216159'
  tag rid: 'SV-216159r603268_rule'
  tag stig_id: 'SOL-11.1-050390'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-17395r372860_fix'
  tag 'documentable'
  tag legacy: ['V-48205', 'SV-61077']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end

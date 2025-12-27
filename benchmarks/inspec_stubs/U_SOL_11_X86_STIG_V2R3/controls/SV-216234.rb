control 'SV-216234' do
  title 'All manual editing of system-relevant files shall be done using the pfedit command, which logs changes made to the files.'
  desc 'Editing a system file with common tools such as vi, emacs, or gedit does not allow the auditing of changes made by an operator. This reduces the capability of determining which operator made security-relevant changes to the system.'
  desc 'check', 'Ask the operators if they use vi, emacs, or gedit to make changes to system files.

If vi, emacs, or gedit are used to make changes to system files, this is a finding.'
  desc 'fix', 'Advise the operators to use pdfedit or other appropriate command line tools to make system changes instead of vi, emacs, or gedit.

Oracle Solaris includes administrative configuration files which use pfedit, and the solaris.admin.edit/path_to_file authorization is not recommended. Alternate commands exist which are both domain-specific and safer. For example, for the /etc/passwd, /etc/shadow, or /etc/user_attr files, use instead passwd, useradd, userdel, or usermod. For the /etc/group file, use instead groupadd, groupdel, or groupmod. For updating /etc/security/auth_attr, /etc/security/exec_attr, or /etc/security/prof_attr, the preferred command is profiles.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17472r373081_chk'
  tag severity: 'low'
  tag gid: 'V-216234'
  tag rid: 'SV-216234r603268_rule'
  tag stig_id: 'SOL-11.1-090240'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17470r373082_fix'
  tag 'documentable'
  tag legacy: ['SV-60809', 'V-47937']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-253112' do
  title 'TOSS must define default permissions for logon and non-logon shells.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0." This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.'
  desc 'check', 'Verify that the umask default for installed shells is "077."

Check for the value of the "UMASK" parameter in the "/etc/bashrc" and "/etc/csh.cshrc" files with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in either the "/etc/bashrc" or the "/etc/csh.cshrc" files, the severity is raised to a CAT I.

$ sudo grep -i umask /etc/bashrc /etc/csh.cshrc

/etc/bashrc:          umask 077
/etc/bashrc:          umask 077
/etc/csh.cshrc:      umask 077   
/etc/csh.cshrc:      umask 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the lines for the "UMASK" parameter in the "/etc/bashrc" and "etc/csh.cshrc" files to "077":

UMASK 077'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56565r825006_chk'
  tag severity: 'medium'
  tag gid: 'V-253112'
  tag rid: 'SV-253112r825008_rule'
  tag stig_id: 'TOSS-04-040710'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56515r825007_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

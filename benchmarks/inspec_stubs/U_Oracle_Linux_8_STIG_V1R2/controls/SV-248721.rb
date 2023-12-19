control 'SV-248721' do
  title 'OL 8 must define default permissions for logon and non-logon shells.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.'
  desc 'check', 'Verify that the umask default for installed shells is "077".

Check for the value of the "UMASK" parameter in the "/etc/bashrc", "/etc/csh.cshrc", and "/etc/profile" files with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in the "/etc/bashrc", "/etc/csh.cshrc", or the "/etc/profile" files, the Severity is raised to a CAT I.

$ sudo  grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile

/etc/bashrc: umask 077
/etc/bashrc: umask 077
/etc/csh.cshrc: umask 077 
/etc/csh.cshrc: umask 077
/etc/profile: umask 077
/etc/profile: umask 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the lines for the "UMASK" parameter in the "/etc/bashrc", "etc/csh.cshrc", and "/etc/profile" files to "077":

UMASK 077'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52155r818664_chk'
  tag severity: 'medium'
  tag gid: 'V-248721'
  tag rid: 'SV-248721r818666_rule'
  tag stig_id: 'OL08-00-020353'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-52109r818665_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

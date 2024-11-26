control 'SV-223840' do
  title 'IBM z/OS UNIX MVS HFS directories with other write permission bit set must be properly defined.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'On the OMVS Command line enter the following command string:
find / -type d -perm -0002 ! -perm -1000 -exec ls -aldWE {} \\;

If there are no directories that have the other write permission bit set on without the sticky bit set on, this is not a finding.

NOTE: In the symbolic permission bit display, the sticky bit is indicated as a "t" or "T" in the execute portion of the other permissions. For example, a display of the permissions of a directory with the sticky bit on could be "drwxrwxrwt".

If all directories that have the other write permission bit set on do not contain any files with the setuid bit set on, this is not a finding.

NOTE: In the symbolic permission bit display, the setuid bit is indicated as an "s" or "S" in the execute portion of the owner permissions. For example, a display of the permissions of a file with the setuid bit on could be "-rwsrwxrwx".

If all directories that have the other write permission bit set on do not contain any files with the setgid bit set on, this is not a finding.

NOTE: In the symbolic permission bit display, the setgid bit is indicated as an "s" or "S" in the execute portion of the group permissions. For example, a display of the permissions of a file with the setgid bit on could be "-rwxrwsrwx".'
  desc 'fix', 'Configure directory permissions as follows:
There are no directories that have the other write permission bit set on without the sticky bit set on.
NOTE: In the symbolic permission bit display, the sticky bit is indicated as a "t" or "T" in the execute portion of the other permissions. For example, a display of the permissions of a directory with the sticky bit on could be "drwxrwxrwt".

All directories that have the other write permission bit set on do not contain any files with the setuid bit set on.
NOTE: In the symbolic permission bit display, the setuid bit is indicated as an "s" or "S" in the execute portion of the owner permissions. For example, a display of the permissions of a file with the setuid bit on could be "-rwsrwxrwx".

All directories that have the other write permission bit set on do not contain any files with the setgid bit set on.
NOTE: In the symbolic permission bit display, the setgid bit is indicated as an "s" or "S" in the execute portion of the group permissions. For example, a display of the permissions of a file with the setgid bit on could be "-rwxrwsrwx".'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25513r868885_chk'
  tag severity: 'medium'
  tag gid: 'V-223840'
  tag rid: 'SV-223840r868887_rule'
  tag stig_id: 'RACF-US-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25501r868886_fix'
  tag 'documentable'
  tag legacy: ['SV-107491', 'V-98387']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

control 'SV-223620' do
  title 'IBM z/OS UNIX MVS HFS directory(s) with other write permission bit set must be properly defined.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'On the OMVS Command line enter the following command string:
find / -type d -perm -0002 ! -perm -1000 -exec ls -aldWE {} \\;

If there are no directories that have the other write permission bit set on without the sticky bit set on, this is not a finding.

NOTE: In the symbolic permission bit display, the sticky bit is indicated as a “t” or “T” in the execute portion of the other permissions. For example, a display of the permissions of a directory with the sticky bit on could be “drwxrwxrwt”.

If all directories that have the other write permission bit set on do not contain any files with the setuid bit set on, this is not a finding.

NOTE: In the symbolic permission bit display, the setuid bit is indicated as an “s” or “S” in the execute portion of the owner permissions. For example, a display of the permissions of a file with the setuid bit on could be “-rwsrwxrwx”.

If all directories that have the other write permission bit set on do not contain any files with the setgid bit set on, this is not a finding.

NOTE: In the symbolic permission bit display, the setgid bit is indicated as an “s” or “S” in the execute portion of the group permissions. For example, a display of the permissions of a file with the setgid bit on could be “-rwxrwsrwx”.'
  desc 'fix', 'Configure directory permissions as follows:
There are no directories that have the other Write permission bit set on without the sticky bit set on.

NOTE: In the symbolic permission bit display, the sticky bit is indicated as a "t" or "T" in the execute portion of the other permissions. For example, a display of the permissions of a directory with the sticky bit on could be “drwxrwxrwt”.

All directories that have the other write permission bit set on do not contain any files with the setuid bit set on.

NOTE: In the symbolic permission bit display, the setuid bit is indicated as an "s" or "S" in the execute portion of the owner permissions. For example, a display of the permissions of a file with the setuid bit on could be "-rwsrwxrwx".

All directories that have the other write permission bit set on do not contain any files with the setgid bit set on.

NOTE: In the symbolic permission bit display, the setgid bit is indicated as an "s" or "S" in the execute portion of the group permissions. For example, a display of the permissions of a file with the setgid bit on could be "-rwxrwsrwx".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25293r504818_chk'
  tag severity: 'medium'
  tag gid: 'V-223620'
  tag rid: 'SV-223620r533198_rule'
  tag stig_id: 'ACF2-US-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25281r504819_fix'
  tag 'documentable'
  tag legacy: ['V-97945', 'SV-107049']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

control 'SV-223625' do
  title 'IBM z/OS UNIX HFS permission bits and audit bits for each directory must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'From the ISPF Command Shell enter:
omvs
cd /
ls -alW

If the HFS permission bits and user audit bits for each directory and file match or are more restrictive than the specified settings listed in the Tale below, this is not a finding.

SYSTEM DIRECTORY SECURITY SETTINGS
DIRECTORY    PERMISSION BITS    USER AUDIT BITS    FUNCTION
/ [root]     755                faf                Root level of all file systems. Holds critical mount points.
/bin         1755               fff                Shell scripts and executables for basic functions
/dev         1755               fff                Character-special files used when logging into the OMVS shell and during C language program compilation.
 Files are created during system IPL and on a per-demand basis.
/etc         1755               faf                Configuration programs and files (usually with locally customized data) used by z/OS UNIX and other product initialization processes
/lib         1755               fff                System libraries including dynamic link libraries and files for static linking
/samples     1755               fff                Sample configuration and other files
/tmp         1777               fff                Temporary data used by daemons, servers, and users.
 Note: /tmp must have the sticky bit on to restrict file renames and deletions.
/u           1755               fff                Mount point for user home directories and optionally for third-party software and other local site files
/usr         1755               fff                Shell scripts, executables, help (man) files and other data.
 Contains sub-directories (e.g., lpp) and mount points used by program products that may be in separate file systems.
/var         1775               fff                Dynamic data used internally by products and by elements and features of z/OS UNIX.

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:
f log for failed access attempts
a log for failed and successful access
- no auditing'
  desc 'fix', 'Define the UNIX permission bits and user audit bits on each of the HFS directory in the table below to be equal or more restrictive.

SYSTEM DIRECTORY SECURITY SETTINGS
DIRECTORY    PERMISSION BITS    USER AUDIT BITS    FUNCTION
/ [root]     755                faf                Root level of all file systems. Holds critical mount points.
/bin         1755               fff                Shell scripts and executables for basic functions
/dev         1755               fff                Character-special files used when logging into the OMVS shell and during C language program compilation.
 Files are created during system IPL and on a per-demand basis.
/etc         1755               faf                Configuration programs and files (usually with locally customized data) used by z/OS UNIX and other product initialization processes
/lib         1755               fff                System libraries including dynamic link libraries and files for static linking
/samples     1755               fff                Sample configuration and other files
/tmp         1777               fff                Temporary data used by daemons, servers, and users.
 Note: /tmp must have the sticky bit on to restrict file renames and deletions.
/u           1755               fff                Mount point for user home directories and optionally for third-party software and other local site files
/usr         1755               fff                Shell scripts, executables, help (man) files and other data.
 Contains sub-directories (e.g., lpp) and mount points used by program products that may be in separate file systems.
/var         1775               fff                Dynamic data used internally by products and by elements and features of z/OS UNIX.

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:
f log for failed access attempts
a log for failed and successful access
- no auditing

The following commands are a sample of the commands to be used (from a user account with an effective UID(0)) to update the permission bits and audit bits:
chmod 0755 /
chaudit w=sf,rx+f /
chmod 0755 /bin
chaudit rwx=f /bin'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25298r504833_chk'
  tag severity: 'medium'
  tag gid: 'V-223625'
  tag rid: 'SV-223625r533198_rule'
  tag stig_id: 'ACF2-US-000100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25286r504834_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-97955', 'SV-107059']
  tag cci: ['CCI-001499', 'CCI-000213']
  tag nist: ['CM-5 (6)', 'AC-3']
end

control 'SV-216323' do
  title 'The operating system must enforce minimum password lifetime restrictions.'
  desc "Passwords need to be changed at specific policy-based intervals; however, if the information system or application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time, defeating the organization's policy regarding password reuse.

Solaris 11.4 introduced new password security features that allow for a more granular approach to password duration parameters. The introduction of MAXDAYS, MINDAYS, and WARNDAYS allow the /etc/default/passwd configuration file to enforce a minimum password lifetime of a single day."
  desc 'check', %q(The root role is required.

Check whether the minimum time period between password changes for each user account is 1 day or greater. 

Determine the OS version you are currently securing.
# uname -v

For Solaris 11, 11.1, 11.2, and 11.3:

# logins -ox |awk -F: '( $1 != "root" && $8 != "LK" && $8 != "NL" && $10 < "1" ) { print }'

If output is returned and the listed account is accessed via direct logon, this is a finding.

Check that /etc/default/password is configured to minimum password change time of 1 week.

# grep "^MINWEEKS=" /etc/default/passwd 

If the command does not report MINWEEKS=1 or more, this is a finding.

For Solaris 11.4 or newer:

# logins -ox |awk -F: '( $1 != "root" && $8 != "LK" && $8 != "NL" && $10 < "1" ) { print }'

If output is returned and the listed account is accessed via direct logon, this is a finding.

Check that /etc/default/password is configured to minimum password change time of 1 day.
Note: It is an error to set both the WEEKS and the DAYS variant for a given MIN/MAX/WARN variable.

# grep "^MINDAYS=" /etc/default/passwd 

If the command does not report MINDAYS=1 or more, this is a finding.

# grep "^MINWEEKS=" /etc/default/passwd 

If output is returned, this is a finding.)
  desc 'fix', 'The root role is required.

For Solaris 11, 11.1, 11.2, and 11.3:

# pfedit /etc/default/passwd file.

Locate the line containing:

MINWEEKS

Change the line to read: 

MINWEEKS=1

Set the per-user minimum password change times by using the following command on each user account. 

# passwd -n [number of days] [accountname]

For Solaris 11.4 or newer:

# pfedit /etc/default/passwd file.
Note: It is an error to set both the WEEKS and the DAYS variant for a given MIN/MAX/WARN variable.

Search for MINDAYS.  Change the line to read: 

MINDAYS=1

Search for MINWEEKS.  Change the line to read: 

#MINWEEKS=

Set the per-user minimum password change times by using the following command on each user account. 

# passwd -n [number of days] [accountname]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17559r622325_chk'
  tag severity: 'medium'
  tag gid: 'V-216323'
  tag rid: 'SV-216323r603863_rule'
  tag stig_id: 'SOL-11.1-040030'
  tag gtitle: 'SRG-OS-000075'
  tag fix_id: 'F-17557r622326_fix'
  tag 'documentable'
  tag legacy: ['SV-60825', 'V-47953']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end

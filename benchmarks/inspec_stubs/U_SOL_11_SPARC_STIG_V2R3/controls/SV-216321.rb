control 'SV-216321' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.

Solaris 11.4 introduced new password security features that allow for a more granular approach to password duration parameters. The introduction of MAXDAYS, MINDAYS, and WARNDAYS allow the /etc/default/passwd configuration file to enforce a password change every 60 Days.'
  desc 'check', %q(The root role is required.

Determine if user passwords are properly configured to be changed every 60 days.

Determine the OS version you are currently securing.
# uname -v

For Solaris 11, 11.1, 11.2, and 11.3:

# logins -ox |awk -F: '( $1 != "root" && $8 != "LK" && $8 != "NL" && ( $11 > “56" || $11 < “1" )) { print }'

If output is returned and the listed account is accessed via direct logon, this is a finding.

Check that /etc/default/password is configured to enforce password expiration every 8 weeks or less.

# grep "^MAXWEEKS=" /etc/default/passwd 

If the command does not report MAXWEEKS=8 or less, this is a finding.

For Solaris 11.4 or newer:

# logins -ox |awk -F: '( $1 != "root" && $8 != "LK" && $8 != "NL" && ($11 > "60"|| $11 < "1")) { print }'

If output is returned and the listed account is accessed via direct logon, this is a finding.

Check that /etc/default/password is configured to enforce password expiration every 60 days or less.
Note: It is an error to set both the WEEKS and the DAYS variant for a given MIN/MAX/WARN variable.

# grep "^MAXDAYS=" /etc/default/passwd 

If the command does not report MAXDAYS=60 or less, this is a finding.

# grep "^MAXWEEKS=" /etc/default/passwd 

If output is returned, this is a finding.)
  desc 'fix', 'The User Security role is required.

For Solaris 11, 11.1, 11.2, and 11.3:

Change each username to enforce 56 day password changes.

# pfexec passwd -x 56 [username]

# pfedit /etc/default/passwd 

Search for MAXWEEKS. Change the line to read:

MAXWEEKS=8

For Solaris 11.4 or newer:

Change each username to enforce 60 day password changes.

# pfexec passwd -x 60 [username]

# pfedit /etc/default/passwd 
Note: It is an error to set both the WEEKS and the DAYS variant for a given MIN/MAX/WARN variable.

Search for MAXDAYS. Change the line to read:

MAXDAYS=60

Search for MAXWEEKS. Change the line to read:

#MAXWEEKS='
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17557r646925_chk'
  tag severity: 'medium'
  tag gid: 'V-216321'
  tag rid: 'SV-216321r646926_rule'
  tag stig_id: 'SOL-11.1-040010'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-17555r622323_fix'
  tag 'documentable'
  tag legacy: ['SV-60815', 'V-47943']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

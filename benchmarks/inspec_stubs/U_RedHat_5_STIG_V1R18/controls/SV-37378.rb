control 'SV-37378' do
  title 'The system must log successful and unsuccessful access to the root account.'
  desc 'If successful and unsuccessful logins and logouts are not monitored or recorded, access attempts cannot be tracked.  Without this logging, it may be impossible to track unauthorized access to the system.'
  desc 'check', 'Check the log files to determine if access to the root account is being logged.

Procedure:
Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file. 
Examine /etc/syslog.conf or /etc/rsyslog.conf to confirm the location to which "authpriv" messages will be directed. The default syslog.conf or rsyslog.conf uses /var/log/messages and /var/log/secure but this needs to be confirmed.

# grep @ /etc/syslog.conf
Or:
# grep @ /etc/rsyslog.conf
If a line starting with "*.*" is returned then all syslog messages will be sent to system whose address appears after the "@". In this case syslog may or may not be configured to also log "authpriv" messages locally.

# grep authpriv /etc/syslog.conf
Or:
# grep authpriv /etc/rsyslog.conf
If any lines are returned which do not start with "#" the "authpriv" messages will be sent to the indicated files or remote systems.

Try to "su -" and enter an incorrect password.

If there are no records indicating the authentication failure, this is a finding.'
  desc 'fix', 'Troubleshoot the system logging configuration to provide for logging of root account login attempts.
Procedure:
Edit /etc/syslog.conf or /etc/rsyslog.conf to make sure "authpriv.*" messages are directed to a file or remote system.
Examine /etc/audit/audit.rules to ensure user authentication messages have not been specifically excluded.
Remove any entries that correspond to:
-a exclude,never -Fmsgtype=USER_START
-a exclude,never -Fmsgtype=USER_LOGIN
-a exclude,never -Fmsgtype=USER_AUTH
-a exclude,never -Fmsgtype=USER_END
-a exclude,never -Fmsgtype=USER_ACCT'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36065r6_chk'
  tag severity: 'medium'
  tag gid: 'V-11980'
  tag rid: 'SV-37378r3_rule'
  tag stig_id: 'GEN001060'
  tag gtitle: 'GEN001060'
  tag fix_id: 'F-31309r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

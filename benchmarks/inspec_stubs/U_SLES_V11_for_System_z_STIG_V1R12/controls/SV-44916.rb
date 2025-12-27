control 'SV-44916' do
  title 'The system must log successful and unsuccessful access to the root account.'
  desc 'If successful and unsuccessful logins and logouts are not monitored or recorded, access attempts cannot be tracked.  Without this logging, it may be impossible to track unauthorized access to the system.'
  desc 'check', 'Check the log files to determine if access to the root account is being logged.

Procedure:
Examine /etc/rsyslog.conf to confirm the location to which "auth" messages will be directed. The default rsyslog.conf uses /var/log/messages but, this needs to be confirmed.

# grep @@ /etc/rsyslog.d/remote.conf
If a line starting with "*.*" is returned then all rsyslog messages will be sent to system whose address appears after the "@@". In this case rsyslog may or may not be configured to also log "auth" messages locally.

# grep auth /etc/rsyslog.conf
If any lines are returned which do not start with "#" the "auth" messages will be sent to the indicated files or remote systems.

Try to "su -" and enter an incorrect password.
#more /var/log/messages
Or
#more /var/log/secure

If there are no records indicating the authentication failure, this is a finding.'
  desc 'fix', 'Troubleshoot the system logging configuration to provide for logging of root account login attempts.
Procedure:
Edit /etc/rsyslog.conf to make sure "auth.*" messages are directed to a file or remote system.
Examine /etc/audit/audit.rules to ensure user authentication messages have not been specifically excluded.
There remove any entries that correspond to:
-a exclude,never -Fmsgtype=USER_START
-a exclude,never -Fmsgtype=USER_LOGIN
-a exclude,never -Fmsgtype=USER_AUTH
-a exclude,never -Fmsgtype=USER_END
-a exclude,never -Fmsgtype=USER_ACCT  

NOTE:  The rsyslogd process is protected by an AppArmor profile.  If the /var/log/secure file needs to be created, the AppArmor profile will need to be updated for the new log file to be used.  The profile is stored in /etc/apparmor.d/sbin.rsyslogd and it can be updated manually or by using the YaST AppArmor profile editor.  An entry like ‘/var/log/secure w,’ allows write access.  A system restart is recommended after updating an AppArmor profile.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11980'
  tag rid: 'SV-44916r1_rule'
  tag stig_id: 'GEN001060'
  tag gtitle: 'GEN001060'
  tag fix_id: 'F-38348r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

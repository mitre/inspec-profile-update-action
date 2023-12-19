control 'SV-215240' do
  title 'AIX must produce audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify the audit daemon is configured for full-text recording of privileged commands: 

The log file can be set by the "trail" variable in /etc/security/audit/config.

# grep trail /etc/security/audit/config
        trail = /audit/trail

Note: The default log file is /audit/trail.

Use the following command to display the audit events:

# /usr/sbin/auditpr -i <audit log file> -v

event           login    status      time                     command           
              wpar name                 
--------------- -------- ----------- ------------------------ ------------------
------------- ------------------------- 
S_PASSWD_READ   root     OK          Sat Aug 26 19:35:00 2017 cron
              Global
        audit object read event detected /etc/security/passwd
S_PASSWD_READ   root     OK          Sat Aug 26 19:35:00 2017 cron
              Global
        audit object read event detected /etc/security/passwd
CRON_Start      root     OK          Sat Aug 26 19:35:00 2017 cron
              Global
        event = start cron job cmd = /usr/sbin/dumpctrl -k >/dev/null 2>/dev/nul
l time = Sat Aug 26 19:35:00 2017
FS_Chdir        root     OK          Sat Aug 26 19:35:00 2017 cron
              Global
        change current directory to: /

If the  full-text recording of privileged command is not displayed, this is a finding. 

More information on the command options used above:
           - v detailed information for the event'
  desc 'fix', 'Reset the audit system with the following command:
# /usr/sbin/audit shutdown

Start the audit system with the following command:
# /usr/sbin/audit start'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16438r294171_chk'
  tag severity: 'medium'
  tag gid: 'V-215240'
  tag rid: 'SV-215240r508663_rule'
  tag stig_id: 'AIX7-00-002006'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-16436r294172_fix'
  tag 'documentable'
  tag legacy: ['V-91255', 'SV-101355']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end

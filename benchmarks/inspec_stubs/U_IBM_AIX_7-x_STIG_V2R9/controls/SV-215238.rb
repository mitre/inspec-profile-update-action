control 'SV-215238' do
  title 'AIX must produce audit records containing information to establish the source and the identity of any individual or process associated with an event.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.
In addition to logging where events occur within AIX, AIX must also generate audit records that identify sources of events. Sources of operating system events include, but are not limited to, processes and services.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.

'
  desc 'check', 'Verify the audit event "process id" is displayed:

The log file can be set by the "trail" variable in /etc/security/audit/config.

# grep trail /etc/security/audit/config
        trail = /audit/trail

Note: The default log file is /audit/trail.

Use the following command to display the audit events:

# /usr/sbin/auditpr -i <audit log file> -helRtcp 

event           login    status      time                     command           
              process  
--------------- -------- ----------- ------------------------ ------------------
------------- -------- 
PROC_Delete     root     OK          Wed Oct 31 23:01:37 2018 audit             
              9437656  
FILE_Close      root     OK          Wed Oct 31 23:01:37 2018 auditbin          
              12255562 
FILE_Open       root     OK          Wed Oct 31 23:01:37 2018 auditbin          
              12255562 
FILE_Read       root     OK          Wed Oct 31 23:01:37 2018 auditbin          
              12255562 
FILE_Close      root     OK          Wed Oct 31 23:01:37 2018 auditbin          
              12255562 
PROC_Create     root     OK          Wed Oct 31 23:01:44 2018 ksh               
              12976466 
FILE_Close      root     OK          Wed Oct 31 23:01:44 2018 ksh               
              9437658  
FILE_Open       root     OK          Wed Oct 31 23:01:44 2018 ksh               
              9437658  
FILE_Read       root     OK          Wed Oct 31 23:01:44 2018 ksh               
              9437658  
FILE_Close      root     OK          Wed Oct 31 23:01:44 2018 ksh               
              9437658  
PROC_Execute    root     OK          Wed Oct 31 23:01:44 2018 ls                
              9437658  
FILE_Open       root     OK          Wed Oct 31 23:01:44 2018 ls                
              9437658  

If user id  or process id is not displayed, this is a finding.

More information on the command options used above:
            -e the audit event.
            -l the login name of the user.
            -R the audit status.
            -t the time the record was written.
            -c the command name.
            -p the process ID.'
  desc 'fix', 'Reset the audit system with the following command:
# /usr/sbin/audit shutdown

Start the audit system with the following command:
# /usr/sbin/audit start'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16436r294165_chk'
  tag severity: 'medium'
  tag gid: 'V-215238'
  tag rid: 'SV-215238r508663_rule'
  tag stig_id: 'AIX7-00-002004'
  tag gtitle: 'SRG-OS-000040-GPOS-00018'
  tag fix_id: 'F-16434r294166_fix'
  tag satisfies: ['SRG-OS-000040-GPOS-00018', 'SRG-OS-000255-GPOS-00096']
  tag 'documentable'
  tag legacy: ['V-91251', 'SV-101351']
  tag cci: ['CCI-000133', 'CCI-001487']
  tag nist: ['AU-3 d', 'AU-3 f']
end

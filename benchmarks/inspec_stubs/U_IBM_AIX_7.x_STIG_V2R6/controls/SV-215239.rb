control 'SV-215239' do
  title 'AIX must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the audit event "status" is displayed:

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

If audit status is not displayed, this is a finding.

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
  tag check_id: 'C-16437r294168_chk'
  tag severity: 'medium'
  tag gid: 'V-215239'
  tag rid: 'SV-215239r508663_rule'
  tag stig_id: 'AIX7-00-002005'
  tag gtitle: 'SRG-OS-000041-GPOS-00019'
  tag fix_id: 'F-16435r294169_fix'
  tag 'documentable'
  tag legacy: ['SV-101353', 'V-91253']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

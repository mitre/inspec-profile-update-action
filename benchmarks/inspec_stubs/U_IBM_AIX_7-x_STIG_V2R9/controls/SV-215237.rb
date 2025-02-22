control 'SV-215237' do
  title 'AIX must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as operating system components, modules, device identifiers, node names, file names, and functionality.

Associating information about where the event occurred within AIX provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify audit event detailed information is displayed:

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
FS_Chdir        root     OK          Sat Aug 26 19:31:37 2017 ps                
              Global                    
        change current directory to: /dev
FS_Chdir        root     OK          Sat Aug 26 19:31:47 2017 ps                
              Global                    
        change current directory to: /dev
FS_Chdir        root     OK          Sat Aug 26 19:31:57 2017 ps                
              Global                    
        change current directory to: /dev
FS_Chdir        root     OK          Sat Aug 26 19:32:07 2017 ps                
              Global                    
        change current directory to: /dev
FS_Chdir        root     OK          Sat Aug 26 19:32:17 2017 ps                
              Global                    
        change current directory to: /dev

If event detailed information is not displayed, this is a finding. 
More information on the command options used above:
           - v detailed information for the event'
  desc 'fix', 'Reset the audit system with the following command:
# /usr/sbin/audit shutdown

Start the audit system with the following command:
# /usr/sbin/audit start'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16435r294162_chk'
  tag severity: 'medium'
  tag gid: 'V-215237'
  tag rid: 'SV-215237r508663_rule'
  tag stig_id: 'AIX7-00-002003'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag fix_id: 'F-16433r294163_fix'
  tag 'documentable'
  tag legacy: ['SV-101349', 'V-91249']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

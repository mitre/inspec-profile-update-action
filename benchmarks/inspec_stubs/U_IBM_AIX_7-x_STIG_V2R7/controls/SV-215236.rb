control 'SV-215236' do
  title 'AIX must produce audit records containing information to establish what the date, time, and type of events that occurred.'
  desc 'Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in AIX audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.

'
  desc 'check', 'Check if audit is turned on by running the following command:

# audit query | grep -i auditing
auditing on

The command should yield the following output:
auditing on

If the command shows "auditing off", this is a finding.

The log file can be set by the "trail" variable in /etc/security/audit/config.
# grep trail /etc/security/audit/config
        trail = /audit/trail

Note: The default log file is "/audit/trail".

Use the following command to display the audit events:

# /usr/sbin/auditpr -i <audit log file> -helRtcp 

event                     login    status      time                                          command      process  
--------------- -------- ----------- ------------------------ ------------------------------- -------- 
PROC_Delete     root     OK           Wed Oct 31 23:01:37 2018    audit             9437656  
FILE_Close           root     OK           Wed Oct 31 23:01:37 2018    auditbin      12255562 
FILE_Open          root      OK           Wed Oct 31 23:01:37 2018    auditbin      12255562 
FILE_Read           root      OK           Wed Oct 31 23:01:37 2018    auditbin      12255562 
FILE_Close          root      OK           Wed Oct 31 23:01:37 2018    auditbin      12255562 
PROC_Create    root      OK           Wed Oct 31 23:01:44 2018     ksh                12976466 
FILE_Close          root     OK           Wed Oct 31 23:01:44 2018      ksh                9437658  
FILE_Open          root     OK           Wed Oct 31 23:01:44 2018     ksh                 9437658  
FILE_Read           root     OK           Wed Oct 31 23:01:44 2018     ksh                9437658  
FILE_Close          root     OK           Wed Oct 31 23:01:44 2018     ksh                9437658  
PROC_Execute  root     OK           Wed Oct 31 23:01:44 2018    ls                    9437658  
FILE_Open          root     OK           Wed Oct 31 23:01:44 2018    ls                    9437658  

If event type is not displayed, this is a finding. 

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
  tag check_id: 'C-16434r294159_chk'
  tag severity: 'medium'
  tag gid: 'V-215236'
  tag rid: 'SV-215236r508663_rule'
  tag stig_id: 'AIX7-00-002001'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-16432r294160_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016']
  tag 'documentable'
  tag legacy: ['SV-101347', 'V-91247']
  tag cci: ['CCI-000130', 'CCI-000131']
  tag nist: ['AU-3 a', 'AU-3 b']
end

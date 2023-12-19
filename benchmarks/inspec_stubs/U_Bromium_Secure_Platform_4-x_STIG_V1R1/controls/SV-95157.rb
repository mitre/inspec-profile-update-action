control 'SV-95157' do
  title 'The Bromium Enterprise Controller (BEC) must manage log record storage capacity so history.log does not exceed physical drive space capacity allocated by the database administrator (DBA) and system administrator.'
  desc 'To ensure applications have a sufficient storage capacity in which to write the audit logs, applications need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the application and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

The BEC administrator must work with site DBA and system administrator to obtain storage allocation requirements for "history.log".

Typical database disk storage consumption is 5 K per day per device. See "Database and Network Usage Guidelines" section in the Bromium Secure Platform Deployment Guide at https://documentation.bromium.com/4_0/Deployment%20Guide/Bromium_Secure_Platform_Deployment_Guide_4_0_Update_3.pdf.'
  desc 'check', %q(Ask the site representatives if they have developed and implemented a solution for storing the contents of "history.log" to minimize the risk of exceeding the system's storage capacity.

If the option to forward the contents of "history.log" to a centralized events server was implemented, check that the agent associated with the central log server has been installed on the BEC.

If the option to back up the contents of "history.log" was implemented, check that the backup solution has been configured to include the "history.log" files residing on the BEC.
 
If the BEC does not manage log record storage capacity so "history.log" does not exceed physical drive space capacity allocated by the DBA and system administrator, this is a finding.)
  desc 'fix', %q(The BEC administrator must work with the site DBA and system administrator to obtain storage allocation requirements for "history.log".

The "history.log" default size threshold is 5 MB. The system administrator has two options for managing storage of "history.log" contents.

Option 1: (Preferred)
1. Automatically forward all contents of "history.log" to the site's central log server in real time. 
2. Install the file monitoring agent that is provided by the site's centralized events server (e.g., syslog, SIEM) and configure to monitor and forward "history.log" (example: C:\Program Data\Bromium\BMS\Logs\history.log). Follow the instructions included with the central log server.

Option 2 (use only with documentation of mission need):
1. Automatically back up all "history.log" files that have been aged out due to reaching maximum size threshold. Then delete the archived copies to free up room.
NOTE: By default, the BEC server creates up to 5 archives. Though not recommended, the default maximum number of archives can be changed by editing the "audit_log_backup_count" parameter in "settings.json". (C:\ProgramData\Bromium\BMS\settings.json)
2. Follow the instructions included with the backup solution. Some solutions include an agent that must be installed on the BEC and some do not.)
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80125r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80453'
  tag rid: 'SV-95157r1_rule'
  tag stig_id: 'BROM-00-000770'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-87259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end

control 'SV-95775' do
  title 'The BlackBerry UEM 12.8 server or platform must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user (a MDM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(2) b"
  desc 'check', 'Review the BlackBerry UEM server configuration to determine whether the system is locked after "15" minutes. 

On the BlackBerry UEM, do the following:
1. Log in to the BlackBerry UEM host server and navigate to “C:\\BlackBerry\\BlackBerry Configuration Tool 1.4.0\\BESConfigTool.exe" and launch the BlackBerry UEM Configuration Tool.
Note: If the BlackBerry UEM Configuration Tool was not installed in the default directory, locate the directory with the executable file to launch the application.
2. Select the "BlackBerry UEM console timeout interval" radio button.
3. Click "Next".
4. Click "Validate" to verify the Database information.
5. Verify the "Session timeout (seconds)" field is populated with "900" or less. 
6. Click "Quit" to exit the application.

Alternately, clock the time on a server to validate that it is correctly enforcing the time period.

If the "Session timeout (seconds)" field is not populated with "900" or less, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM, do the following:
1. Log in to the BlackBerry UEM host server and navigate to “C:\\BlackBerry\\BlackBerry Configuration Tool 1.4.0\\BlackBerry UEMConfigTool.exe" to launch the BlackBerry UEM Configuration Tool.
Note: If the BlackBerry UEM Configuration Tool was not installed in the default directory, locate the directory with the executable file to launch the application.
2. Select the "BlackBerry UEM console timeout interval" radio button.
3. Click "Next".
4. Click "Validate" to verify the Database information.
5. In the "Session timeout (seconds)" field enter "900" or less. 
6. Select the check box next to "Automatically Restart Services".
7. Click "Update".
8. Verify that the message "BlackBerry UEM services successfully restarted" is displayed when the process is completed.
Note: If the services do not restart automatically, restart the services manually.
9. Click "Quit" to exit the application.

Note: If the BlackBerry UEM Configuration Tool is not installed on the host system, download and install the tool on the host server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-80747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81063'
  tag rid: 'SV-95775r1_rule'
  tag stig_id: 'BUEM-12-807800'
  tag gtitle: 'PP-MDM-311047'
  tag fix_id: 'F-87865r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-000366', 'CCI-001310', 'CCI-002450']
  tag nist: ['IA-5 (2) (b) (1)', 'CM-6 b', 'SI-10', 'SC-13 b']
end

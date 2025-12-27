control 'SV-243126' do
  title 'The vCenter Server must terminate management sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

By default, vSphere Client sessions terminate after "120" minutes of idle time, requiring the user to log in again to resume using the client. You can view the timeout value by viewing the "webclient.properties" file.

On the vCenter Server locate the "webclient.properties" file in 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client

Find the "session.timeout =" line in the "webclient.properties" file.

If the session timeout is not set to "10" in the "webclient.properties" file, this is a finding.'
  desc 'fix', 'Change the timeout value by editing the "webclient.properties" file.

On the vCenter Server locate the "webclient.properties" file in 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client

Edit the file to include the line "session.timeout = 10" where "10" is the timeout value in minutes.  Uncomment the line if necessary.

After editing the file the vSphere Client service must be restarted.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46401r719619_chk'
  tag severity: 'medium'
  tag gid: 'V-243126'
  tag rid: 'SV-243126r879622_rule'
  tag stig_id: 'VCTR-67-000071'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-46358r719620_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

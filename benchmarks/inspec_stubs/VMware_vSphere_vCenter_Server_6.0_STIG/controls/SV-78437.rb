control 'SV-78437' do
  title 'The system must terminate management sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'By default, vSphere Web Client sessions terminate after 120 minutes of idle time, requiring the user to log in again to resume using the client. You can view the timeout value by viewing the webclient.properties file.

On the system where vCenter is installed locate the webclient.properties file.

Windows: C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client
Appliance: /etc/vmware/vsphere-client/

Find the session.timeout = line in the webclient.properties file.

If the session timeout is not set to 10 in the webclient.properties file, this is a finding.'
  desc 'fix', 'You can change the timeout value by editing the webclient.properties file.

On the system where vCenter is installed locate the webclient.properties file.

Windows: C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client
Appliance: /etc/vmware/vsphere-client/

Edit the file to include the line "session.timeout = 10" where 10 is the timeout value in minutes.  Uncomment the line if necessary.

After editing the file the vSphere Web Client service must be restarted.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64697r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63947'
  tag rid: 'SV-78437r1_rule'
  tag stig_id: 'VCWN-06-000004'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-69875r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

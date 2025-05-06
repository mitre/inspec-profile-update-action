control 'SV-83797' do
  title 'The NSX vCenter must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses a network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 
 
Session termination terminates all processes associated with an administrator's logical session except those processes that are specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 
 
Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types."
  desc 'check', 'Verify the vSphere Web Client sessions terminate after 10 minutes of idle time, requiring the user to log on again to resume using the client. View the timeout value by viewing the webclient.properties file.
 
On the system where vCenter is installed, locate the webclient.properties file.
 
Windows: C:\\ProgramData\\VMware\\vCenter Server\\cfg\\vsphere-client
 
Find the session.timeout = line in the webclient.properties file.
 
If the session timeout is not set to 10 in the webclient.properties file, this is a finding.'
  desc 'fix', 'Change the timeout value by editing the webclient.properties file.
 
On the system where vCenter is installed, locate the webclient.properties file.
 
Windows: C:\\ProgramData\\VMware\\vCenter Server\\cfg\\vsphere-client
 
Edit the file to include the line "session.timeout = 10" where 10 is the timeout value in minutes. Uncomment the line if necessary.
 
After editing the file, the vSphere Web Client service must be restarted.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69193'
  tag rid: 'SV-83797r1_rule'
  tag stig_id: 'VNSX-ND-000083'
  tag gtitle: 'SRG-APP-000295-NDM-000279'
  tag fix_id: 'F-75379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end

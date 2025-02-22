control 'SV-216851' do
  title 'The vCenter Server for Windows must enable all tasks to be shown to Administrators in the Web Client.'
  desc "By default not all tasks are shown in the web client to administrators and only that user's tasks will be shown.  Enabling all tasks to be shown will allow the administrator to potentially see any malicious activity they may miss with the view disabled."
  desc 'check', 'Verify the "webclient.properties" file contains the line "show.allusers.tasks = true".

The default location for the "webclient.properties" file are:

Appliance: 
/etc/vmware/vsphere-client/ 

Windows: 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client\\

If "show.allusers.tasks" is not set to "true", this is a finding.'
  desc 'fix', 'Edit the "webclient.properties" file to set the "show.allusers.tasks" value to "true".

The default location for the "webclient.properties" file are:

Appliance: 
/etc/vmware/vsphere-client/ 

Windows: 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client\\

After editing the file the vSphere Web Client service will need to be restarted.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18082r366267_chk'
  tag severity: 'medium'
  tag gid: 'V-216851'
  tag rid: 'SV-216851r612237_rule'
  tag stig_id: 'VCWN-65-000029'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18080r366268_fix'
  tag 'documentable'
  tag legacy: ['SV-104597', 'V-94767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

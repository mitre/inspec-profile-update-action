control 'SV-243130' do
  title 'The vCenter Server must enable all tasks to be shown to Administrators in the Web Client.'
  desc "By default not all tasks are shown in the web client to administrators and only that user's tasks will be shown.  Enabling all tasks to be shown will allow the administrator to potentially see any malicious activity they may miss with the view disabled."
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

Verify the "webclient.properties" file contains the line "show.allusers.tasks = true".

On the vCenter Server locate the "webclient.properties" file in 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client

If "show.allusers.tasks" is not set to "true", this is a finding.'
  desc 'fix', 'Edit the "webclient.properties" file to set the "show.allusers.tasks" value to "true".

On the vCenter Server locate the "webclient.properties" file in 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client

After editing the file the vSphere Client service will need to be restarted.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46405r719631_chk'
  tag severity: 'medium'
  tag gid: 'V-243130'
  tag rid: 'SV-243130r719633_rule'
  tag stig_id: 'VCTR-67-000075'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46362r719632_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

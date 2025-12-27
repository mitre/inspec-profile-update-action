control 'SV-78485' do
  title 'The system must enable all tasks to be shown to Administrators in the Web Client.'
  desc "By default not all tasks are shown in the web client to administrators and only that user's tasks will be shown.  Enabling all tasks to be shown will allow the administrator to potentially see any malicious activity they may miss with the view disabled."
  desc 'check', 'Verify the webclient.properties file contains the line "show.allusers.tasks = true".

The default locations for the webclient.properties file are:

Windows - C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client\\

Appliance - /etc/vmware/vsphere-client/

If show.allusers.tasks is not set to true, this is a finding.'
  desc 'fix', 'Edit the webclient.properties file to set the show.allusers.tasks setting to true.

The default locations for the webclient.properties file are:

Windows - C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client\\

Appliance - /etc/vmware/vsphere-client/

After editing the file the vSphere Web Client service will need to be restarted.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63995'
  tag rid: 'SV-78485r1_rule'
  tag stig_id: 'VCWN-06-000029'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69927r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

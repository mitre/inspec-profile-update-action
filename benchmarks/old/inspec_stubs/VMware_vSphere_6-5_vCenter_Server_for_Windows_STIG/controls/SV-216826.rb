control 'SV-216826' do
  title 'The vCenter Server for Windows must not automatically refresh client sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. Automatic client session refreshes keep unused sessions online, blocking session timeouts.'
  desc 'check', 'On the system where vCenter is installed locate the "webclient.properties" file. 

Appliance: 
/etc/vmware/vsphere-client/ 

Windows: 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client 

Find the "refresh.rate =" line in the "webclient.properties" file. 

If the refresh rate is not set to "-1" in the "webclient.properties" file, this is a finding.'
  desc 'fix', 'Change the refresh rate value by editing the "webclient.properties" file. 

On the system where vCenter is installed locate the "webclient.properties" file. 

Appliance: 
/etc/vmware/vsphere-client/ 

Windows: 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client 

Edit the file to include the line "refresh.rate = -1" where "-1" indicates sessions are not automatically refreshed. Uncomment the line if necessary. 

After editing the file the vSphere Web Client service must be restarted.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18057r366192_chk'
  tag severity: 'medium'
  tag gid: 'V-216826'
  tag rid: 'SV-216826r879622_rule'
  tag stig_id: 'VCWN-65-000002'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-18055r366193_fix'
  tag 'documentable'
  tag legacy: ['SV-104547', 'V-94717']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

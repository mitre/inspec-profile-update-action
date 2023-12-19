control 'SV-243125' do
  title 'The vCenter Server must not automatically refresh client sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. Automatic client session refreshes keep unused sessions online, blocking session timeouts.'
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

On the vCenter Server locate the "webclient.properties" file in 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client 

Find the "refresh.rate =" line in the "webclient.properties" file. 

If the refresh rate is not set to "-1" in the "webclient.properties" file, this is a finding.'
  desc 'fix', 'Change the refresh rate value by editing the "webclient.properties" file. 

On the vCenter Server locate the "webclient.properties" file in 
C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client 

Edit the file to include the line "refresh.rate = -1" where "-1" indicates sessions are not automatically refreshed. Uncomment the line if necessary. 

After editing the file the vSphere Client service must be restarted.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46400r719616_chk'
  tag severity: 'medium'
  tag gid: 'V-243125'
  tag rid: 'SV-243125r879622_rule'
  tag stig_id: 'VCTR-67-000070'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-46357r719617_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

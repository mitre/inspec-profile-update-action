control 'SV-243109' do
  title 'The vCenter Server must enable the vSAN Health Check.'
  desc 'The vSAN Health Check is used for additional alerting capabilities, performance stress testing prior to production usage, and verifying that the underlying hardware officially is supported by being in compliance with the vSAN Hardware Compatibility Guide.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select a vSAN Enabled Cluster >> Configure >> vSAN >> Services >> Health Service. 

Review the "Health Service Status" and verify that it is set to "Enabled".

If vSAN is enabled and the vSAN Health Service is disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vSAN Enabled Cluster >> Configure >> vSAN >> Services. 

Click "Edit" next to "Health Service". 

Click the slider to "Turn On Periodical Health Check" and configure the time interval as necessary (default is 60 minutes).'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46384r719568_chk'
  tag severity: 'medium'
  tag gid: 'V-243109'
  tag rid: 'SV-243109r719570_rule'
  tag stig_id: 'VCTR-67-000053'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46341r719569_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

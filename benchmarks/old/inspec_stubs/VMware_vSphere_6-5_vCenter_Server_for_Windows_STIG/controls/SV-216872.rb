control 'SV-216872' do
  title 'The vCenter Server for Windows must enable the vSAN Health Check.'
  desc 'The vSAN Health Check is used for additional alerting capabilities, performance stress testing prior to production usage, and verifying that the underlying hardware officially is supported by being in compliance with the vSAN Hardware Compatibility Guide'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a vSAN Enabled Cluster >> Manage >> Configure >> Virtual SAN >> Health and Performance. Review the "Health Service Status" and verify that it is set to "Enabled".

If vSAN is enabled and there is no vSAN health check installed or the vSAN Health Check is disabled, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters >> Select a vSAN Enabled Cluster >> Manage >> Configure >> Virtual SAN >> Health and Performance >> "Health Service" and click "Edit Settings". Select the check box for "Turn On Periodical Health Check" and configure the time interval as necessary.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18103r366330_chk'
  tag severity: 'medium'
  tag gid: 'V-216872'
  tag rid: 'SV-216872r879887_rule'
  tag stig_id: 'VCWN-65-000053'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18101r366331_fix'
  tag 'documentable'
  tag legacy: ['SV-104639', 'V-94809']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

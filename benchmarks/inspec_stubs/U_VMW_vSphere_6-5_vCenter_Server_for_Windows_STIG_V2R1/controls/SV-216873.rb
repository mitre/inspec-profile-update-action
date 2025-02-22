control 'SV-216873' do
  title 'The vCenter Server for Windows must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List by use of an external proxy server.'
  desc 'The vSAN Health Check is able to download the hardware compatibility list from VMware in order to check compliance against the underlying vSAN Cluster hosts. To ensure the vCenter server is not directly downloading content from the internet this functionality must be disabled or if this feature is necessary an external proxy server must be configured.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a vSAN Enabled Cluster >> Manage >> Configure >> Virtual SAN >> General >> Internet Connectivity >> Edit

If the HCL internet download is not required then ensure that "Enable Internet access for this cluster" is disabled. 

If this "Enable Internet access for this cluster" is enabled, this is a finding.

If the HCL internet download is required then ensure that "Enable Internet access for this cluster" is enabled and that a proxy host is configured. 

If "Enable Internet access for this cluster" is disabled or a proxy is not configured, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters >> Select a vSAN Enabled Cluster >> Manage >> Configure >> Virtual SAN >> General >> Internet Connectivity >> Edit

If the HCL internet download is not required then ensure that "Enable Internet access for this cluster" is disabled.

If the HCL internet download is required then ensure that "Enable Internet access for this cluster" is enabled and that a proxy host is appropriately configured.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18104r366333_chk'
  tag severity: 'medium'
  tag gid: 'V-216873'
  tag rid: 'SV-216873r612237_rule'
  tag stig_id: 'VCWN-65-000054'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18102r366334_fix'
  tag 'documentable'
  tag legacy: ['V-94811', 'SV-104641']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-87793' do
  title 'The connectivity between VSAN Health Check and public Hardware Compatibility List must be disabled or restricted by use of an external proxy server.'
  desc 'The VSAN Health Check is able to download the hardware compatibility list from VMware in order to check compliance against the underlying VSAN Cluster hosts. To ensure the vCenter server is not directly downloading content from the internet this functionality must be disabled or if this feature is necessary an external proxy server must be configured.'
  desc 'check', 'If no clusters are enabled for VSAN, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a VSAN Enabled Cluster >> Manage >> Settings >> General >> Internet Connectivity >> Edit

If the HCL internet download is not required then ensure that "Enable Internet access for this cluster" is disabled. 

If this "Enable Internet access for this cluster" is enabled this is a finding.

If the HCL internet download is required then ensure that "Enable Internet access for this cluster" is enabled and that a proxy host is configured. 

If "Enable Internet access for this cluster" is disabled or a proxy is not configured this is a finding.'
  desc 'fix', 'If no clusters are enabled for VSAN, this is not applicable.

If VSAN Health Check is not installed (6.0 GA only): 
Download the VSAN Health Check Plugin and install to the vCenter Server. Then restart the vCenter Server services. DRS must be configured for fully automated on the cluster. Then each ESXi host must have the VSAN Health Check VIB installed on the ESXi hosts.

If VSAN Health Check is installed:
From the vSphere Web Client go to Host and Clusters > Select a VSAN Enabled Cluster > Manage > Settings > General > Internet Connectivity > Edit

If the HCL internet download is not required then ensure that "Enable Internet access for this cluster" is disabled.

If the HCL internet download is required then ensure that "Enable Internet access for this cluster" is enabled and that a proxy host is appropriately configured.'
  impact 0.3
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-73275r2_chk'
  tag severity: 'low'
  tag gid: 'V-73141'
  tag rid: 'SV-87793r1_rule'
  tag stig_id: 'VCWN-06-000053'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-79587r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

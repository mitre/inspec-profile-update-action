control 'SV-243110' do
  title 'The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List by use of an external proxy server.'
  desc 'The vSAN Health Check is able to download the hardware compatibility list from VMware to check compliance against the underlying vSAN Cluster hosts. 

To ensure the vCenter server is not directly downloading content from the internet, this functionality must be disabled or, if this feature is necessary, an external proxy server must be configured.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Hosts and Clusters >> select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

If the HCL internet download is not required, verify that "Status" is disabled. 

If the "Status" is enabled, this is a finding.

If the HCL internet download is required, verify that "Status" is enabled and a proxy host is configured. 

If "Status" is enabled and a proxy is not configured, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> vCenter Server >> Configure >> vSAN >> Internet Connectivity >> Edit.

If the HCL internet download is not required, ensure that "Status" is disabled.

If the HCL internet download is required, ensure that "Status" is enabled and a proxy host is appropriately configured.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46385r719571_chk'
  tag severity: 'medium'
  tag gid: 'V-243110'
  tag rid: 'SV-243110r879887_rule'
  tag stig_id: 'VCTR-67-000054'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46342r719572_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

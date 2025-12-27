control 'SV-258948' do
  title 'The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List (HCL) by use of an external proxy server.'
  desc 'The vSAN Health Check is able to download the HCL from VMware to check compliance against the underlying vSAN Cluster hosts. To ensure the vCenter server is not directly downloading content from the internet, this functionality must be disabled. If this feature is necessary, an external proxy server must be configured.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

If the HCL internet download is not required, verify "Status" is "Disabled".

If the "Status" is "Enabled", this is a finding.

If the HCL internet download is required, verify "Status" is "Enabled" and a proxy host is configured.

If "Status" is "Enabled" and a proxy is not configured, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

Click "Edit".

If the HCL internet download is not required, ensure that "Status" is "Disabled".

If the HCL internet download is required, ensure that "Status" is "Enabled" and that a proxy host is appropriately configured.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62688r934500_chk'
  tag severity: 'medium'
  tag gid: 'V-258948'
  tag rid: 'SV-258948r934502_rule'
  tag stig_id: 'VCSA-80-000281'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62597r934501_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-250667' do
  title 'The system must prevent unintended use of dvfilter network APIs.'
  desc 'If products that use the dvfilter network API are not used, the host should not be configured to send network information to a VM. If the API is enabled, an attacker might attempt to connect a VM to it, thereby potentially providing access to the network of other VMs on the host.

If a product uses this API, the host must be verified as being correctly configured.'
  desc 'check', 'From the vSphere client select the host and click "Configuration >> Advanced Settings >> Net" and verify the value of Net.DVFilterBindIpAddress. 

For a host without a dvfilter-based network security appliance, the following kernel parameter value must be blank/empty: /Net/DVFilterBindIpAddress. 

For a host with a dvfilter-based network security appliance is being used, the value of this parameter must be set to match the appliance.

If a dvfilter-based network security appliance is not used and the kernel parameter /Net/DVFilterBindIpAddress is populated, this is a finding.

If a dvfilter-based network security appliance is used and the kernel parameter /Net/DVFilterBindIpAddress does not match the appliance, this is a finding.'
  desc 'fix', 'From the vSphere client select the host and click "Configuration >> Advanced Settings >> Net" 
Set the value of Net.DVFilterBindIpAddress to blank if a dvfilter-based network security appliance is not used or (where used) set the value of Net.DVFilterBindIpAddress to match the dvfilter-based network security appliance.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54102r798998_chk'
  tag severity: 'low'
  tag gid: 'V-250667'
  tag rid: 'SV-250667r799000_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000151'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54056r798999_fix'
  tag 'documentable'
  tag legacy: ['V-39346', 'SV-51204']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

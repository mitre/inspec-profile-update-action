control 'SV-250673' do
  title 'The system must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory.'
  desc 'ESXi hosts configured to join an Active Directory domain using host profiles do not protect the passwords used for host authentication. To avoid transmitting clear text passwords, the vSphere Authentication Proxy must be used to configure hosts in an Active Directory.'
  desc 'check', 'For systems that do not use Active Directory and have no local user accounts, other than root and/or vpxuser, this check is not applicable.

NOTE:  vSphere Authentication Proxy is available via the vSphere vCenter Server ISO. Although mainly used with Auto Deploy, which is available only with the vSphere Enterprise Plus Edition, vSphere Authentication Proxy does not require a specific vSphere Edition (i.e., Standard vs Enterprise) to be installed.

From the vSphere client, select "Host Profiles". Right click the Host Profile and select Edit. Choose "Authentication configuration >> Active Directory Configuration >> Join Domain Method". Verify the Join Domain Method is set to "Use vSphere Authentication Proxy to add the host to domain".

If the vSphere Authentication Proxy is installed and the Join Domain Method is not set to "Use vSphere Authentication Proxy to add the host to domain", this is a finding.'
  desc 'fix', 'From the vSphere client, select "Host Profiles". Right click the Host Profile and select Edit. Choose "Authentication configuration >> Active Directory Configuration >> Join Domain Method". Set the Join Domain Method to "Use vSphere Authentication Proxy to add the host to domain".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54108r799016_chk'
  tag severity: 'medium'
  tag gid: 'V-250673'
  tag rid: 'SV-250673r799018_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000160'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54062r799017_fix'
  tag 'documentable'
  tag legacy: ['V-39352', 'SV-51210']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

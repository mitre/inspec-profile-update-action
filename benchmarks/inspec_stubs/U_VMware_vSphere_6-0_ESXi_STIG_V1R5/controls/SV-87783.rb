control 'SV-87783' do
  title 'The system must enable the VSAN Health Check.'
  desc 'VSAN Health Check is enabled by default in vSphere 6.0 update 1 and later, it has to be manually installed and enabled on vSphere 6.0.0 prior to usage. The VSAN Health check is used for additional alerting capabilities, performance stress testing prior to production usage, and verifying that the underlying hardware officially is supported by being in compliance with the VSAN Hardware Compatibility Guide'
  desc 'check', 'If no clusters are enabled for VSAN, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a Cluster >> Manage >> Settings >> Virtual SAN >> Health. Review the "Health Service Status" and verify that it is set to "Enabled".

If VSAN is enabled and there is no VSAN health check installed or the VSAN health check is disabled, this is a finding.'
  desc 'fix', 'If VSAN Health Check is not installed (6.0 GA only): 
Download the VSAN Health Check Plugin and install to the vCenter Server. Then restart the vCenter Server services. DRS must be configured for fully automated on the cluster. Then each ESXi host must have the VSAN Health Check VIB installed on the ESXi hosts.

If VSAN Health Check is installed: 
From the vSphere Web Client go to Host and Clusters >> Select a VSAN enabled "Cluster" >> Manage >> Settings >> Virtual SAN >> Health >> "Health Service Status" and click "Edit Settings". Select the check box for "Turn On Periodical Health Check" and configure the time interval as necessary.'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-73265r3_chk'
  tag severity: 'low'
  tag gid: 'V-73131'
  tag rid: 'SV-87783r1_rule'
  tag stig_id: 'ESXI-06-000074'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-79577r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-250726' do
  title 'The VMware Update Manager must not be configured to manage its own VM or the VM of its vCenter Server.'
  desc 'The VMware Update Manager (vUM) and vCenter Server (vCS) are VM installable on an ESXi hypervisor host. For all ESXi hypervisors and VMs, including those of the vCS and the vUM, software and system security patches must be installed and up-to-date. For the use case where the vUM hypervisor/VM or the vCS hypervisor/VM reboots while undergoing remediation, this will halt that process. Note that for the use case where the vCS hypervisor/VM reboots, the result is a worst case scenario of a temporary, unplanned vCS outage.'
  desc 'check', "Ask the SA if software and system security patches are installed and up-to-date for all ESXi hypervisors/VMs, including the vCenter Server (vCS) and the VMware Update Manager (vUM), if they are also installed as VMs rather than as physical machines. 

If the vUM's hypervisor host/VM patch, update, and remediation procedure does not include its own hypervisor/VM or that of the vCS (if installed as VMs), this check is not a finding. 

If the vUM's hypervisor host/VM patch, update, and remediation process also includes its own hypervisor  host/VM  and/or the vCS's hypervisor host/VM, this is a finding."
  desc 'fix', 'Determine if both the VMware Update Manager (vUM) and vCenter Server (vCS) are installed as physical or virtual machines. 

No fix is required for vCS/vUM if the vCS and vUM are both installed as physical machines.

If the vCS and vUM are installed as virtual machines, they must both be managed either manually or by a secondary installation of vCS and the vUM. 

All remaining organization hypervisor hosts/VMs must be configured to receive software and security patch updates, via the vUM, on an organization-defined, regularly scheduled basis.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54161r799866_chk'
  tag severity: 'medium'
  tag gid: 'V-250726'
  tag rid: 'SV-250726r799868_rule'
  tag stig_id: 'VCENTER-000003'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54115r799867_fix'
  tag 'documentable'
  tag legacy: ['SV-51402', 'V-39544']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

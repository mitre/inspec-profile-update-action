control 'SV-251043' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of VMM components from which information can be transmitted (e.g., guest VMs, servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'From the vSphere Web Client, select the ESXi Host and go to Manage >> Networking >> VMkernel adapters. Review each VMkernel adapter that is defined and ensure it is enabled for only one type of management traffic.

If any VMkernel is used for more than one type of management traffic, this is a finding.'
  desc 'fix', 'From the vSphere Web Client, select the ESXi Host and go to Configure >> Networking >> VMkernel adapters >> Select a VMkernel Adapter >> Click Edit settings >> Uncheck any additional services that have been enabled on the VMkernel adapter so that there is only one service left checked.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-54478r854584_chk'
  tag severity: 'medium'
  tag gid: 'V-251043'
  tag rid: 'SV-251043r854585_rule'
  tag stig_id: 'ESXI-65-000049'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-54431r802908_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

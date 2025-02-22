control 'SV-77761' do
  title 'The system must protect the confidentiality and integrity of transmitted information.'
  desc 'There are now six types of management VMkernels that can be created for different types of traffic.  In order to protect these types of management traffic admins must logically separate these onto different networks and dedicate VMkernel ports to each.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Networking >> VMkernel adapters.  Review each VMkernel adapter that is defined and ensure it is enabled for only one type of management traffic.

If any VMkernel is used for more than one type of management traffic, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Networking >> VMkernel adapters >> Select a VMkernel Adapter >> Click Edit >> Uncheck any additional services that have been enabled on the VMkernel adapter so that there is only one service left checked.'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64005r1_chk'
  tag severity: 'low'
  tag gid: 'V-63271'
  tag rid: 'SV-77761r1_rule'
  tag stig_id: 'ESXI-06-000051'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-69189r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

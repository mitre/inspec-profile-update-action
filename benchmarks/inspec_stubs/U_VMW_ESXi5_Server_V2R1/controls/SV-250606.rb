control 'SV-250606' do
  title 'The DHCP client must be disabled if not used.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'check', 'If DHCP is used, this is not applicable.

From the vSphere Client/vCenter, click on the "Configuration" tab; click on "Networking"; click on "Standard Switch/Properties";  click on "Management NetworkProperties/Edit/IP Settings"; verify "Obtain IP settings  automatically" is not selected, and click "Cancel".

If "Obtain IP settings automatically" is selected, this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter, click on the "Configuration" tab; click on "Networking"; click on "Standard Switch/Properties";  click on "Management NetworkProperties/Edit/IP Settings"; select "Use the following IP settings"; fill in the IPAddress fields per local site requirements and click "OK".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54041r798815_chk'
  tag severity: 'medium'
  tag gid: 'V-250606'
  tag rid: 'SV-250606r798817_rule'
  tag stig_id: 'GEN007840-ESXI5-000119'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53995r798816_fix'
  tag 'documentable'
  tag legacy: ['SV-51103', 'V-39287']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

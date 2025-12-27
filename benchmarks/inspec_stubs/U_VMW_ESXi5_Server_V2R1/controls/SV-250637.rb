control 'SV-250637' do
  title 'The system must be configured with a default gateway for IPv4 if the system uses IPv4, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial-of-Service attacks.'
  desc 'check', 'From the vSphere Client/vCenter:  Click on the Configuration tab, Click on the DNS and Routing tabs, and verify that the default gateway information is entered and Click "Cancel". 

If the default gateway field has not been initialized (IP address is required), this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter, click on the Configuration tab; click on DNS and Routing; click on Properties/DNS and Routing, Configuration/Routing. Add a default gateway (IP address is required). Click "OK"'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54072r798908_chk'
  tag severity: 'medium'
  tag gid: 'V-250637'
  tag rid: 'SV-250637r798910_rule'
  tag stig_id: 'SRG-OS-000145-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54026r798909_fix'
  tag 'documentable'
  tag legacy: ['V-39395', 'SV-51253']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

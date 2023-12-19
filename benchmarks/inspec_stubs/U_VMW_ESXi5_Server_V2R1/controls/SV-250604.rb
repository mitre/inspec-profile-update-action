control 'SV-250604' do
  title 'The system must be configured with a default gateway for IPv6 if the system uses IPv6, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial-of-Service attacks. NOTE that IPv6 is not enabled by default.'
  desc 'check', 'If the system does not use IPv6, this check is not applicable. 

From the vSphere Client/vCenter; click on the "Configuration" tab, click on "Networking"; click on "Standard Switch/Properties"; click on "Management NetworkProperties/Edit/IP Settings" and click "Cancel".  

If the "VMkernel Default Gateway" field is not initialized (valid IP address is required), this is a finding.'
  desc 'fix', 'The following fix text applies only if the system uses IPv6. From the vSphere Client/vCenter; click on the "Configuration" tab; click on "Networking"; click on "Standard Switch/Properties"; click on "Management NetworkProperties/Edit/IP Settings". Select "Use the following IP settings"; fill in the field(s) (at a minimum, the default gateway IP Address is required) per the local site requirements and click "OK".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54039r798809_chk'
  tag severity: 'medium'
  tag gid: 'V-250604'
  tag rid: 'SV-250604r798811_rule'
  tag stig_id: 'GEN005570-ESXI5-000115'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53993r798810_fix'
  tag 'documentable'
  tag legacy: ['SV-51102', 'V-39286']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

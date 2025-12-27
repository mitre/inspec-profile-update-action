control 'SV-250570' do
  title 'The system clock must be synchronized to an authoritative DoD time source.'
  desc 'To assure the accuracy of the system clock, it must be synchronized with an authoritative time source within DoD. Many system functions, including time-based login and activity restrictions, automated reports, system logs, and audit records depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.'
  desc 'check', %q(From the vSphere Client:  Select the host and click "Configuration >> Time Configuration".  Select the properties link and chose 'Options'.  Select NTP Settings to view configured NTP servers. 

If NTP is not synchronized with an authoritative time source within DoD, this is a finding.)
  desc 'fix', %q(From the vSphere Client:  Select the host and click "Configuration >> Time Configuration".  Select the properties link and chose 'Options'.  From the General tab start the NTP service and select "Start and stop with host".  From the NTP Settings tab click the ' Add' button to add the organization defined, authoritative time source within DoD NTP servers.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54005r798707_chk'
  tag severity: 'medium'
  tag gid: 'V-250570'
  tag rid: 'SV-250570r798709_rule'
  tag stig_id: 'GEN000240-ESXI5-000058'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53959r798708_fix'
  tag 'documentable'
  tag legacy: ['SV-51288', 'V-39430']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

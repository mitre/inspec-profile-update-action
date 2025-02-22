control 'SV-250617' do
  title 'The system must use time sources local to the enclave.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. The network architecture should provide multiple time servers (at least two) within an enclave providing local service to the enclave and synchronize with time sources outside of the enclave.'
  desc 'check', %q(From the vSphere Client:  Select the host and click Configuration >> Time Configuration". Select the properties link and chose 'Options'. Select NTP Settings to view configured NTP servers. 

If NTP is not configured to use NTP server(s) local to the enclave, this is a finding.)
  desc 'fix', %q(From the vSphere Client:  Select the host and click Configuration >> Time Configuration".  Select the properties link and chose 'Options'.  From the General tab start the NTP service and select "Start and stop with host". From the NTP Settings tab click the 'Add' button to add NTP server(s) local to the enclave.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54052r798848_chk'
  tag severity: 'medium'
  tag gid: 'V-250617'
  tag rid: 'SV-250617r798850_rule'
  tag stig_id: 'SRG-OS-000056-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54006r798849_fix'
  tag 'documentable'
  tag legacy: ['V-39254', 'SV-51070']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-250720' do
  title 'The system must use secure protocols for virtual serial port access.'
  desc 'Serial ports are interfaces for connecting peripherals to the virtual machine. They are often used on physical systems to provide a direct, low-level connection to the console of a server, and a virtual serial port allows for the same access to a virtual machine. Serial ports allow for low-level access, which often does not have strong controls like logging or privileges.'
  desc 'check', 'Ask the SA if a secure protocol like SSH or Telnets (Telnet with SSL) as opposed to Telnet to access virtual serial ports. Note that SSH is preferred to Telnets.


If Telnet is used, this is a finding.'
  desc 'fix', 'Use a secure protocol like SSH or Telnets (Telnet with SSL) as opposed to Telnet to access virtual serial ports. Note that SSH is preferred to Telnets.'
  impact 0.5
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54155r799620_chk'
  tag severity: 'medium'
  tag gid: 'V-250720'
  tag rid: 'SV-250720r799622_rule'
  tag stig_id: 'ESXI5-VM-000049'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54109r799621_fix'
  tag 'documentable'
  tag legacy: ['SV-51361', 'V-39503']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

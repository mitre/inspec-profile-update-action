control 'SV-208869' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.'
  desc 'Disabling TIPC protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'If the system is configured to prevent the loading of the "tipc" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r tipc /etc/modprobe.conf /etc/modprobe.d | grep -i “/bin/true”

If no line is returned, this is a finding.'
  desc 'fix', 'The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the "tipc" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install tipc /bin/true'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9122r357587_chk'
  tag severity: 'medium'
  tag gid: 'V-208869'
  tag rid: 'SV-208869r793654_rule'
  tag stig_id: 'OL6-00-000127'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9122r357588_fix'
  tag 'documentable'
  tag legacy: ['SV-65211', 'V-51005']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

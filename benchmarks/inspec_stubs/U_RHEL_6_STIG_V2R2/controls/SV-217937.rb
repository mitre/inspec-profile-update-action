control 'SV-217937' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.'
  desc 'Disabling TIPC protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'If the system is configured to prevent the loading of the "tipc" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r tipc /etc/modprobe.conf /etc/modprobe.d | grep -i “/bin/true”| grep -v “#”

If no line is returned, this is a finding.'
  desc 'fix', 'The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the "tipc" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install tipc /bin/true'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19418r462400_chk'
  tag severity: 'medium'
  tag gid: 'V-217937'
  tag rid: 'SV-217937r603264_rule'
  tag stig_id: 'RHEL-06-000127'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19416r462401_fix'
  tag 'documentable'
  tag legacy: ['V-38517', 'SV-50318']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

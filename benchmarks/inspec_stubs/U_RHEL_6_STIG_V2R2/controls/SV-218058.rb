control 'SV-218058' do
  title 'The Bluetooth kernel module must be disabled.'
  desc 'If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation.'
  desc 'check', 'If the system is configured to prevent the loading of the "bluetooth" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"| grep -v "#"

If no line is returned, this is a finding.

If the system is configured to prevent the loading of the "net-pf-31" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true" | grep -v "#"

If no line is returned, this is a finding.'
  desc 'fix', %q(The kernel's module loading system can be configured to prevent loading of the Bluetooth module. Add the following to the appropriate "/etc/modprobe.d" configuration file to prevent the loading of the Bluetooth module: 

install net-pf-31 /bin/true
install bluetooth /bin/true)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19539r377189_chk'
  tag severity: 'medium'
  tag gid: 'V-218058'
  tag rid: 'SV-218058r603264_rule'
  tag stig_id: 'RHEL-06-000315'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19537r377190_fix'
  tag 'documentable'
  tag legacy: ['V-38682', 'SV-50483']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

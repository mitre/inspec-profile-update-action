control 'SV-221846' do
  title 'The Oracle Linux operating system must implement virtual address space randomization.'
  desc "Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return-oriented programming (ROP) techniques."
  desc 'check', 'Verify the operating system implements virtual address space randomization.

     # grep -r kernel.randomize_va_space /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out or does not have a value of "2", this is a finding.

Check that the operating system implements virtual address space randomization with the following command:

     # /sbin/sysctl -a | grep kernel.randomize_va_space 
     kernel.randomize_va_space = 2

If "kernel.randomize_va_space" does not have a value of "2", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system implement virtual address space randomization.

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

     kernel.randomize_va_space = 2

Issue the following command to make the changes take effect:

     # sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23561r880628_chk'
  tag severity: 'medium'
  tag gid: 'V-221846'
  tag rid: 'SV-221846r880630_rule'
  tag stig_id: 'OL07-00-040201'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-23550r880629_fix'
  tag 'documentable'
  tag legacy: ['SV-108535', 'V-99431']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end

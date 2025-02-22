control 'SV-217909' do
  title 'The system must implement virtual address space randomization.'
  desc "Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques."
  desc 'check', 'The status of the "kernel.randomize_va_space" kernel parameter can be queried by running the following commands: 

$ sysctl kernel.randomize_va_space
   kernel.randomize_va_space = 2

$ grep kernel.randomize_va_space /etc/sysctl.conf /etc/sysctl.d/*
kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "2", this is a finding.'
  desc 'fix', 'To set the runtime status of the "kernel.randomize_va_space" kernel parameter, run the following command: 

# sysctl -w kernel.randomize_va_space=2

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

kernel.randomize_va_space = 2

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19390r376742_chk'
  tag severity: 'medium'
  tag gid: 'V-217909'
  tag rid: 'SV-217909r603264_rule'
  tag stig_id: 'RHEL-06-000078'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19388r376743_fix'
  tag 'documentable'
  tag legacy: ['V-38596', 'SV-50397']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

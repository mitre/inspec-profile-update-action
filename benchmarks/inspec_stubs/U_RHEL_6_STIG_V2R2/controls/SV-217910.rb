control 'SV-217910' do
  title 'The system must limit the ability of processes to have simultaneous write and execute access to memory.'
  desc "ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range."
  desc 'check', 'The status of the "kernel.exec-shield" kernel parameter can be queried by running the following command: 

$ sysctl kernel.exec-shield
 kernel.exec-shield = 1

$ grep kernel.exec-shield /etc/sysctl.conf /etc/sysctl.d/*
kernel.exec-shield = 1

If "kernel.exec-shield" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "1", this is a finding.'
  desc 'fix', 'To set the runtime status of the "kernel.exec-shield" kernel parameter, run the following command: 

# sysctl -w kernel.exec-shield=1

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

kernel.exec-shield = 1   

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19391r376745_chk'
  tag severity: 'medium'
  tag gid: 'V-217910'
  tag rid: 'SV-217910r603264_rule'
  tag stig_id: 'RHEL-06-000079'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19389r376746_fix'
  tag 'documentable'
  tag legacy: ['V-38597', 'SV-50398']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

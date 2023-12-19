control 'SV-208848' do
  title 'The system must implement virtual address space randomization.'
  desc "Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques."
  desc 'check', 'The status of the "kernel.randomize_va_space" kernel parameter can be queried by running the following commands: 

$ sysctl kernel.randomize_va_space
$ grep kernel.randomize_va_space /etc/sysctl.conf

The output of the command should indicate a value of at least "1" (preferably "2"). If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "kernel.randomize_va_space" kernel parameter, run the following command: 

# sysctl -w kernel.randomize_va_space=2

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

kernel.randomize_va_space = 2)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9101r357524_chk'
  tag severity: 'medium'
  tag gid: 'V-208848'
  tag rid: 'SV-208848r793633_rule'
  tag stig_id: 'OL6-00-000078'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9101r357525_fix'
  tag 'documentable'
  tag legacy: ['SV-65163', 'V-50957']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

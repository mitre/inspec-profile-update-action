control 'SV-216210' do
  title 'The centralized process core dump data directory must be owned by root.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the centralized process core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the defined directory for process core dumps.
# coreadm | grep "global core file pattern"

Check the ownership of the directory.
# ls -lLd [core file directory]

If the directory is not owned by root, this is a finding.'
  desc 'fix', 'The root role is required.

Change the owner of the core file directory. 

# chown root [core file directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17448r373012_chk'
  tag severity: 'medium'
  tag gid: 'V-216210'
  tag rid: 'SV-216210r603268_rule'
  tag stig_id: 'SOL-11.1-080050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17446r373013_fix'
  tag 'documentable'
  tag legacy: ['V-48019', 'SV-60891']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

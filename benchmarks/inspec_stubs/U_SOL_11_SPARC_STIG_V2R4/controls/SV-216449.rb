control 'SV-216449' do
  title 'The centralized process core dump data directory must have mode 0700 or less permissive.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the process core dump data directory has a mode more permissive than 0700, unauthorized users may be able to view or to modify sensitive information contained in any process core dumps in the directory.'
  desc 'check', 'Check the defined directory for process core dumps.
# coreadm | grep "global core file pattern"

Check the permissions of the directory.

# ls -lLd [core file directory]

If the directory has a mode more permissive than 0700 (rwx --- ---), this is a finding.'
  desc 'fix', 'The root role is required.

Change the mode of the core file directory. 

# chmod 0700 [core file directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17685r371435_chk'
  tag severity: 'medium'
  tag gid: 'V-216449'
  tag rid: 'SV-216449r603267_rule'
  tag stig_id: 'SOL-11.1-080070'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17683r371436_fix'
  tag 'documentable'
  tag legacy: ['SV-60887', 'V-48015']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

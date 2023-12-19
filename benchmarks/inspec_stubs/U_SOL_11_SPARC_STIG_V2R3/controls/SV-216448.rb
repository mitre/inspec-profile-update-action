control 'SV-216448' do
  title 'The centralized process core dump data directory must be group-owned by root, bin, or sys.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the centralized process core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the defined directory for process core dumps.
# coreadm | grep "global core file pattern"

Check the group ownership of the directory.
# ls -lLd [core file directory]

If the directory is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'The root role is required.

Change the group-owner of the core file directory to root, bin, or sys.

Example: # chgrp root [core file directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-36488r603067_chk'
  tag severity: 'medium'
  tag gid: 'V-216448'
  tag rid: 'SV-216448r603267_rule'
  tag stig_id: 'SOL-11.1-080060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36452r603068_fix'
  tag 'documentable'
  tag legacy: ['SV-60889', 'V-48017']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-216211' do
  title 'The centralized process core dump data directory must be group-owned by root, bin, or sys.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the centralized process core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the defined directory for process core dumps.
# coreadm | grep "global core file pattern"

Check the group ownership of the directory.
# ls -lLd [core file directory]

If the directory is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'The root role is required.

Change the group-owner of the core file directory to root, bin or sys.

Example: # chgrp root [core file directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-36492r603079_chk'
  tag severity: 'medium'
  tag gid: 'V-216211'
  tag rid: 'SV-216211r603268_rule'
  tag stig_id: 'SOL-11.1-080060'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36456r603080_fix'
  tag 'documentable'
  tag legacy: ['V-48017', 'SV-60889']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-226878' do
  title 'The centralized process core dump data directory must be group-owned by root, bin, or sys.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the centralized process core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the defined directory for process core dumps.

# coreadm | grep "global core file pattern"
OR 
# grep COREADM_GLOB_PATTERN /etc/coreadm.conf

Check the group ownership of the directory.
# ls -lLd [core file directory]
If the directory is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the core file directory to root, bin, or sys.
Example: # chgrp root [core file directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36400r602803_chk'
  tag severity: 'low'
  tag gid: 'V-226878'
  tag rid: 'SV-226878r603265_rule'
  tag stig_id: 'GEN003503'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36364r602804_fix'
  tag 'documentable'
  tag legacy: ['V-22401', 'SV-26582']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

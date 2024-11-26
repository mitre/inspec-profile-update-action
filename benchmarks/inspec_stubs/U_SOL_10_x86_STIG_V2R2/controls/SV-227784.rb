control 'SV-227784' do
  title 'The centralized process core dump data directory must have mode 0700 or less permissive.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the process core dump data directory has a mode more permissive than 0700, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', 'Check the defined directory for process core dumps.

# coreadm | grep "global core file pattern"
OR
# grep COREADM_GLOB_PATTERN /etc/coreadm.conf

Check the permissions of the directory.
# ls -lLd [core file directory]
If the directory has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the core file directory.
# chmod 0700 [core file directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29946r489706_chk'
  tag severity: 'low'
  tag gid: 'V-227784'
  tag rid: 'SV-227784r603266_rule'
  tag stig_id: 'GEN003504'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29934r489707_fix'
  tag 'documentable'
  tag legacy: ['SV-26596', 'V-22402']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

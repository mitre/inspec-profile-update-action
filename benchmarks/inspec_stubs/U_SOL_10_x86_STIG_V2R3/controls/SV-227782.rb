control 'SV-227782' do
  title 'The centralized process core dump data directory must be owned by root.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the centralized process core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the defined directory for process core dumps.

# coreadm | grep "global core file pattern"
OR
# grep COREADM_GLOB_PATTERN /etc/coreadm.conf

Check the ownership of the directory.
# ls -lLd [core file directory]
If the directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the core file directory.
# chown root [core file directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29944r489700_chk'
  tag severity: 'low'
  tag gid: 'V-227782'
  tag rid: 'SV-227782r603266_rule'
  tag stig_id: 'GEN003502'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29932r489701_fix'
  tag 'documentable'
  tag legacy: ['V-22400', 'SV-26579']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

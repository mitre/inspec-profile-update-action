control 'SV-226877' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29039r484915_chk'
  tag severity: 'low'
  tag gid: 'V-226877'
  tag rid: 'SV-226877r603265_rule'
  tag stig_id: 'GEN003502'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29027r484916_fix'
  tag 'documentable'
  tag legacy: ['V-22400', 'SV-26579']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

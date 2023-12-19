control 'SV-226880' do
  title 'The centralized process core dump data directory must not have an extended ACL.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the process core dump data directory has an extended ACL, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', 'Check the defined directory for process core dumps.

# coreadm | grep "global core file pattern"
OR
# grep COREADM_GLOB_PATTERN /etc/coreadm.conf

Check the permissions of the directory.
# ls -lLd [core file directory]
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the directory.
# chmod A- [core file directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29042r484924_chk'
  tag severity: 'low'
  tag gid: 'V-226880'
  tag rid: 'SV-226880r603265_rule'
  tag stig_id: 'GEN003505'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29030r484925_fix'
  tag 'documentable'
  tag legacy: ['SV-26602', 'V-22403']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

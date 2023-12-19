control 'SV-26612' do
  title 'The kernel core dump data directory must have mode 0700 or less permissive.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the mode of the kernel core dump data directory is more permissive than 0700, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'fix', 'Set the permissions on the kernel core dump data directory to 0700.
# chmod 0700 <kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22406'
  tag rid: 'SV-26612r2_rule'
  tag stig_id: 'GEN003522'
  tag gtitle: 'GEN003522'
  tag fix_id: 'F-31610r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

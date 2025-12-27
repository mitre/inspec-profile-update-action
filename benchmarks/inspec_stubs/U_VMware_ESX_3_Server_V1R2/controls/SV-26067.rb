control 'SV-26067' do
  title 'The kernel core dump data directory must have mode 0700 or less permissive.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the mode of the kernel core dump data directory is more permissive than 0700, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', 'Determine the mode of the kernel core dump data directory.
# ls -lLd <directory>
If the mode is more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the kernel core dump data directory to 0700.
# chmod 0700 <directory>'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29244r1_chk'
  tag severity: 'low'
  tag gid: 'V-22406'
  tag rid: 'SV-26067r1_rule'
  tag stig_id: 'GEN003522'
  tag gtitle: 'GEN003522'
  tag fix_id: 'F-26263r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

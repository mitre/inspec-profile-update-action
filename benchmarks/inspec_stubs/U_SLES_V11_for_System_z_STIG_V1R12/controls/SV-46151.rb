control 'SV-46151' do
  title 'The system must be configured to store any process core dumps in a specific, centralized directory.'
  desc 'Specifying a centralized location for core file creation allows for the centralized protection of core files.  Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If process core dump creation is not configured to use a centralized directory, core dumps may be created in a directory that does not have appropriate ownership or permissions configured, which could result in unauthorized access to the core dumps.'
  desc 'check', 'Verify a directory is defined for process core dumps.
# cat /proc/sys/kernel/core_pattern
If the parameter is not an absolute path (does not start with a slash [/]), this is a finding.'
  desc 'fix', 'Edit /etc/sysctl.conf and set (adding if necessary) kernel.core_pattern to an absolute path ending with a file name prefix, such as "/var/core/core".'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43412r1_chk'
  tag severity: 'low'
  tag gid: 'V-22399'
  tag rid: 'SV-46151r1_rule'
  tag stig_id: 'GEN003501'
  tag gtitle: 'GEN003501'
  tag fix_id: 'F-39490r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

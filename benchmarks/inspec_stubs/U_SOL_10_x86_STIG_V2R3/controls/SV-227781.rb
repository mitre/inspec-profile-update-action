control 'SV-227781' do
  title 'The system must be configured to store any process core dumps in a specific, centralized directory.'
  desc 'Specifying a centralized location for core file creation allows for the centralized protection of core files.  Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If process core dump creation is not configured to use a centralized directory, core dumps may be created in a directory that does not have appropriate ownership or permissions configured, which could result in unauthorized access to the core dumps.'
  desc 'check', 'Verify a directory is defined for process core dumps.

# grep COREADM_GLOB_PATTERN /etc/coreadm.conf

If the parameter is not an absolute path (does not start with a slash [/]), this is a finding.'
  desc 'fix', 'Change the core file pattern.
# coreadm -g /var/core/core.%f.%p

Then:
# coreadm -u
In order to force a reload of the configuration.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29943r489697_chk'
  tag severity: 'low'
  tag gid: 'V-227781'
  tag rid: 'SV-227781r603266_rule'
  tag stig_id: 'GEN003501'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29931r489698_fix'
  tag 'documentable'
  tag legacy: ['V-22399', 'SV-26576']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

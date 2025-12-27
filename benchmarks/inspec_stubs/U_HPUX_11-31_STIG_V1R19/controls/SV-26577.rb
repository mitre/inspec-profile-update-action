control 'SV-26577' do
  title 'The system must be configured to store any process core dumps in a specific, centralized directory.'
  desc 'Specifying a centralized location for core file creation allows for the centralized protection of core files. Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If process core dump creation is not configured to use a centralized directory, core dumps may be created in a directory without appropriate ownership or permissions configured, which could result in unauthorized access to the core dumps.'
  desc 'check', %q(View all coreadm configuration settings.
# coreadm

Or

View only if a directory is defined for process core dumps. If no information is returned, a directory has not been defined.
# coreadm | tr '\011' ' ' | tr -s ' ' | egrep -i "global core file pattern|global core dumps" 


If the process core dump directory is undefined and core dumps are disabled, this is not applicable.

If the process core dump directory is defined with a relative path (does not start with a slash "/") and core dumps are enabled, this is a finding.)
  desc 'fix', 'Change the core file pattern.
# coreadm -I /var/adm/crash/core.%f.%p

Where:

%f = Will be assigned the executable/program file name creating the core
%p = Will be assigned the executable/program process ID creating the core

Ensure that core dumps are enabled:
# coreadm -e global'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36488r2_chk'
  tag severity: 'low'
  tag gid: 'V-22399'
  tag rid: 'SV-26577r1_rule'
  tag stig_id: 'GEN003501'
  tag gtitle: 'GEN003501'
  tag fix_id: 'F-31840r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

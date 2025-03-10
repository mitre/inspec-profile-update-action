control 'SV-26992' do
  title 'The system package management tool must not automatically obtain updates.'
  desc "System package management tools can obtain a list of updates and patches from a package repository and make this information available to the SA for review and action. Using a package repository outside of the organization's control presents a risk of malicious packages being introduced."
  desc 'check', 'Verify the YUM service is enabled.
# service yum-updatesd status
If the service is enabled, this is a finding.'
  desc 'fix', 'Disable the yum service.
# chkconfig yum-updatesd off ; service yum-updatesd stop'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27935r1_chk'
  tag severity: 'low'
  tag gid: 'V-22589'
  tag rid: 'SV-26992r1_rule'
  tag stig_id: 'GEN008820'
  tag gtitle: 'GEN008820'
  tag fix_id: 'F-24258r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end

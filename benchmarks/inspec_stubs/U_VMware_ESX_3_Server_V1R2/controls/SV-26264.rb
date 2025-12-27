control 'SV-26264' do
  title 'The system package management tool must not automatically obtain updates.'
  desc "System package management tools can obtain a list of updates and patches from a package repository and make this information available to the SA for review and action. Using a package repository outside of the organization's control, presents a risk that malicious packages could be introduced."
  desc 'check', 'Determine if the system package management tool is configured to automatically obtain updated packages. If it is, this is a finding.'
  desc 'fix', 'Configure the system package management tool not to  automatically obtain updates.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29324r1_chk'
  tag severity: 'low'
  tag gid: 'V-22589'
  tag rid: 'SV-26264r1_rule'
  tag stig_id: 'GEN008820'
  tag gtitle: 'GEN008820'
  tag fix_id: 'F-26356r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end

control 'SV-242576' do
  title "The Cisco ISE must enforce approved access by employing authorization policies with specific attributes; such as resource groups, device type, certificate attributes, or any other attributes that are specific to a group of endpoints, and/or mission conditions as defined in the site's Cisco ISE System Security Plan (SSP). This is required for compliance with C2C Step 4."
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the unauthorized network access.

Configuration policy sets with specific authorization policies. Policies consist of rules, where each rule consists of conditions to be met that allow differential access based on grouping of device types by common attributes.

ISE requires each authorization policy to have at a minimum one condition. The default authorization policy is the only policy in which there is not a requirement for a condition, nor is it possible to assign a condition to the default authorization policy.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify that the authorization policies have either "deny-access" or restricted access on their default authorization policy set. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.

If the default authorization policy within each policy set has "deny-access" or restricted access, this is not a finding.'
  desc 'fix', 'Configure each policy set so that authorization policies have either "deny-access" or restricted access on their default authorization policy set. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.

On the default authorization rule select "Deny-Access" or a result that is configured for a restricted VLAN, ACL, SGT, or any combination used to restrict the access.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45851r812733_chk'
  tag severity: 'high'
  tag gid: 'V-242576'
  tag rid: 'SV-242576r812734_rule'
  tag stig_id: 'CSCO-NC-000020'
  tag gtitle: 'SRG-NET-000015-NAC-000020'
  tag fix_id: 'F-45808r714037_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

control 'SV-233314' do
  title 'Forescout must be configured so that all client machines are assessed by Forescout with exceptions that are allowed to bypass Forescout based on account or account type, as approved by the Information System Security Manager (ISSM) and documented in the System Security Plan (SSP).'
  desc "The NAC gateway provides the policy enforcement allowing or denying the traffic to the network. Unauthorized traffic that bypasses this control presents a risk to the organization's data and network.

Forescout allows exception by User Names or individual MAC or IP addresses. DoD requires the best practice of using a group and applying policy to the group."
  desc 'check', 'If traffic is not allowed to bypass the NAC policy, this is not a finding.

Verify a policy exists that uses the exemption group configured so that all client machines are assessed by Forescout with exceptions that are allowed to bypass Forescout based on account or account type, as approved by the ISSM and documented in the SSP.

1. In the filters pane under Groups, right-click the group editor. Pick the group indicated as compliance by the site representative.
2. Click "Scope" and review the Exemptions Group.

If remediation is being performed, ensure the ISSM has approved any bypass procedure configured in the NAC.

If Forescout is not configured to approve all instances where traffic is allowed to bypass the NAC as approved by the ISSM, this is a finding.'
  desc 'fix', 'Forescout allows exception by User Names or individual MAC or IP addresses. DoD requires the best practice of using a group and applying policy to the group. 

Create a group based on the exemptions in the SSP.

1. In the filters pane under Groups, right-click the group editor. Pick or create an exemption group.
2. Add a name, then add the scope based on IP range or Subnet, or add based on MAC Address.
3. Click "OK", and then "OK" again. Click "Yes" for "Are you sure?".

Create a policy that uses the exemption group.

1. In the Views pane, click "Authentication & Authorization".
2. Select an existing policy and Edit the Scope to add the Exemptions Group.
3. In Exceptions type, select "Group".
4. In the Policy screen, select the exceptions group created in the prior step, click "OK" several times, and then click "Apply".'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36509r605645_chk'
  tag severity: 'high'
  tag gid: 'V-233314'
  tag rid: 'SV-233314r615869_rule'
  tag stig_id: 'FORE-NC-000060'
  tag gtitle: 'SRG-NET-000015-NAC-000080'
  tag fix_id: 'F-36474r615852_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

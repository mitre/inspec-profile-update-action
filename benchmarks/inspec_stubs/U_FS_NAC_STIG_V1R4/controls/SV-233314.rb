control 'SV-233314' do
  title 'Forescout must be configured so that all client machines are assessed by Forescout with exceptions that are allowed to bypass Forescout based on account or account type, as approved by the information system security manager (ISSM) and documented in the System Security Plan (SSP). This is required for compliance with C2C Step 1.'
  desc "The NAC gateway provides the policy enforcement allowing or denying the endpoint to the network. Unauthorized endpoints that bypass this control present a risk to the organization's data and network.

The focus of this requirement is on identification, documentation, and approval of devices that will bypass the NAC. This is not a requirement that all traffic flow through the NAC."
  desc 'check', 'If DOD is not at C2C Step 1 or higher, this is not a finding.

If traffic is not allowed to bypass the NAC policy, this is not a finding.

Use the Forescout Administrator UI to verify a policy exists that uses the exemption group configured so that all client machines are assessed by Forescout with exceptions that are allowed to bypass Forescout based on the account or account type, as approved by the ISSM and documented in the SSP.

1. In the filters pane under Groups, right-click the group editor. Pick the group indicated as compliance by the site representative.
2. Click "Scope" and review the Exemptions Group.

If Forescout is not configured to approve all instances where traffic is allowed to bypass the NAC as approved by the ISSM, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure an exception group that is defined in the SSP and ensure policy is applied to the group that allows NAC bypass.

Create a group based on the exemptions in the SSP.

1. In the filters pane under Groups, right-click the group editor. Pick or create an exemption group.
2. Add a name and then add the scope based on IP range or Subnet, or based on MAC Address.
3. Click "OK" and then click "OK" again. Click "Yes" for "Are you sure?".

Create a policy that uses the exemption group.

1. In the Views pane, click "Authentication & Authorization".
2. Select an existing policy and edit the Scope to add the Exemptions Group.
3. In Exceptions type, select "Group".
4. In the Policy screen, select the exceptions group created in the prior step, click "OK" several times, and then click "Apply".'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36509r919217_chk'
  tag severity: 'high'
  tag gid: 'V-233314'
  tag rid: 'SV-233314r919219_rule'
  tag stig_id: 'FORE-NC-000060'
  tag gtitle: 'SRG-NET-000015-NAC-000080'
  tag fix_id: 'F-36474r919218_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

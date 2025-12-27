control 'SV-242577' do
  title 'The Cisco ISE must be configured to profile endpoints connecting to the network. This is required for compliance with C2C Step 4.'
  desc 'It is possible for endpoints to be manually added to an incorrect endpoint identity group. The endpoint policy can be dynamically set through profiling. If the endpoint group is statically set but the endpoint policy is set to dynamic, then it is possible to identify endpoints that may receive unintended access.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify the profiling service is configured and enabled.

1. Choose Administration >> System >> Deployment.
2. View the Deployment Nodes.

Verify the following services are enabled via the check box:
Policy Service
Enable Session Services 
Enable Profiling Services

If the Cisco ISE profiling service is not configured and enabled, this is a finding.'
  desc 'fix', 'Configure the profiling service to provide a contextual inventory of all the endpoints that are using your network resources in any Cisco ISE-enabled network.

1. Choose Administration >> System >> Deployment.
2. Choose a Cisco ISE node that assumes the Policy Service persona.
3. Click "Edit" in the Deployment Nodes page.
4. On the "General Settings" tab, check the "Policy Service" check box.
5. Perform the following tasks:
- Check the "Enable Session Services" check box. 
- Check the "Enable Profiling Services" check box to run the profiling service.
6. Click "Save" to save the node configuration.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45852r812735_chk'
  tag severity: 'high'
  tag gid: 'V-242577'
  tag rid: 'SV-242577r812736_rule'
  tag stig_id: 'CSCO-NC-000030'
  tag gtitle: 'SRG-NET-000015-NAC-000020'
  tag fix_id: 'F-45809r714040_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

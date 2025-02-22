control 'SV-8533' do
  title 'All external connections must be validated and approved by the Authorizing Official (AO) and the Connection Approval Office (CAO) and meeting Connection Approval Process (CAP) requirements.'
  desc 'Every site must have a security policy to address filtering of the traffic to and from those connections.  This documentation along with diagrams of the network topology is required to be submitted to the Connection Approval Process (CAP) for approval to connect to the NIPRNet or SIPRNet.  SIPRNet connections must also comply with the documentation required by the Classified Connection Approval Office (CCAO) to receive the SIPRNet Interim Approval to Connect (IATC) or final Approval to Connect (ATC). Also any additional requirements must be met as outlined in the Interim Authority to Operate (IATO) or Authority to Operate (ATO) forms signed by the Authorizing Official (AO).'
  desc 'check', 'Review the network topology and interview the ISSO to verify that each external connection to the site’s network has been validated and approved by the AO and CAO and that CAP requirements have been met.

If there are any external connections that have not been validated and approved, this is a finding.'
  desc 'fix', 'All external connections will be validated and approved prior to connection. Interview the ISSM to verify that all connections have a mission requirement and that the AO is aware of the requirement.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7428r3_chk'
  tag severity: 'medium'
  tag gid: 'V-8047'
  tag rid: 'SV-8533r3_rule'
  tag stig_id: 'NET0130'
  tag gtitle: 'Network connections exist without approval'
  tag fix_id: 'F-7622r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001121']
  tag nist: ['SC-7 (14)']
end

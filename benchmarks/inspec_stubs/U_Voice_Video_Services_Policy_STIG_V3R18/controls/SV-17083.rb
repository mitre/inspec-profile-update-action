control 'SV-17083' do
  title 'Implementing Unified Capabilities (UC) soft clients as the primary voice endpoint must have Authorizing Official (AO) approval.'
  desc 'The AO responsible for the implementation of a voice system that uses UC soft clients for its endpoints must be made aware of the risks and benefits. In addition, the commander of an organization whose mission depends upon such a telephone system must also be made aware and provide approval. When UC soft clients are fielded as the primary endpoint, the risk of unavailability is high compared to dedicated instruments. Another major difficulty for UC soft clients deployed on laptops is providing accurate location information for emergency services. When emergency services are called from the laptop, if it is not at the location entered in the Automated Location Identification (ALI) database, emergency services may be dispatched to the wrong place.'
  desc 'check', 'Ensure the Command and AO approves the implementation or transition to UC soft clients as the primary endpoints in writing. Approval documentation will be maintained by the ISSO for inspection by IA reviewers or auditors.

Review the written Command and AO approval for the implementation of a telephone system which primarily uses UC soft client applications for its endpoints. 

If no written Command and AO approval exist for UC soft client endpoints, this is a finding.'
  desc 'fix', 'Obtain the Command and AO approval for the implementation or transition to UC soft clients as the primary endpoints in writing. Approval documentation must be maintained by the ISSO for future inspection by IA reviewers or auditors. If Command and AO written approval is not available, hardware endpoints must be used as the primary endpoints.

Note: This requirement is in addition to AO approval for deploying UC soft clients on DoD networks (VVoIP 1720). When UC soft clients are deployed as the primary endpoint, additional risks to availability exist.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17139r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16095'
  tag rid: 'SV-17083r2_rule'
  tag stig_id: 'VVoIP 1110'
  tag gtitle: 'VVoIP 1110'
  tag fix_id: 'F-16200r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
end

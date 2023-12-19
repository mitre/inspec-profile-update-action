control 'SV-85993' do
  title 'The CA API Gateway must protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session, rather than for the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOAP will require the use of mutual authentication (two-way/bidirectional).

To protect authenticity of communications sessions, the CA API Gateway includes the "Require SSL or TLS Transport with Client Certificate Authentication" Assertion which includes options for Mutual Authentication such as requiring the client initiating the communication to authenticate with a trusted certificate. The CA API Gateway must utilize this assertion within Registered services or within Global policy to help create protection against man-in-the-middle attacks/session hijacking and the insertion of false information into a session allowing both the client and destination server to trust and authenticate against each other before communications can occur.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require the protection of communications sessions or mutual authentication. 

Optionally, if a Global Policy has been set, double-click that policy to inspect the contents. 

If the "Require SSL or TLS Transport with Client Certificate Authentication" Assertion is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that do not have the "Require SSL or TLS Transport with Client Certificate Authentication" Assertion.

Optionally, if a Global Policy has been set, double-click that policy to inspect the contents. 

Add the "Require SSL or TLS Transport with Client Certificate Authentication" Assertion to the policy and click "Save and Activate".'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71369'
  tag rid: 'SV-85993r1_rule'
  tag stig_id: 'CAGW-GW-000400'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-77679r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

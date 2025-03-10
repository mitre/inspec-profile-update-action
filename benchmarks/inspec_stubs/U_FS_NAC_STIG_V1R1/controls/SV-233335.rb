control 'SV-233335' do
  title 'Forescout must generate a log record when the client machine fails policy assessment because required security software is missing or has been deleted.'
  desc 'Generating log records with regard to modules and policies is an important part of maintaining proper cyber hygiene. Keeping and maintaining the logs helps to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.'
  desc 'check', 'Verify the policy assessment device uses TLS 1.2 to protect the confidentiality of the communication between the endpoint and the NAC.

1. Log on to the Forescout UI.
2. Select Tools >> Option >> HPS Inspection Engine >> SecureConnector.
3. In the Client-Server Connection, check the Minimum Supported TLS Version is set to TLS version 1.2.

If the NAC does not use TLS 1.2, at a minimum, to protect the confidentiality of information passed between the endpoint agent and the NAC for the purposes of client posture assessment, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI.

1. Select Tools >> Option >> HPS Inspection Engine >> SecureConnector.
2. In the Client-Server Connection, set the Minimum Supported TLS Version to TLS version 1.2.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36530r605708_chk'
  tag severity: 'medium'
  tag gid: 'V-233335'
  tag rid: 'SV-233335r616546_rule'
  tag stig_id: 'FORE-NC-000340'
  tag gtitle: 'SRG-NET-000492-NAC-002110'
  tag fix_id: 'F-36495r616545_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

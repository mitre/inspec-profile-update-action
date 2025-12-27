control 'SV-79723' do
  title 'The DataPower Gateway must protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).'
  desc 'check', 'Using the WebGUI at Objects >> Crypto Configuration >> SSL Client Profile and SSL Server Profile. 

Select the profiles that are configured for the application session requiring mutual authentication. Confirm that the correct protocol and cipher parameters are set and that the correct identification and validation credentials are specified.

If these items are not configured, this is a finding.'
  desc 'fix', 'Using the WebGUI at Objects >> Crypto Configuration >> SSL Client Profile and SSL Server Profile. 

Create a client and server profile for the application session requiring mutual authentication. Specify the correct protocol and cipher parameters and the correct identification and validation credentials.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65233'
  tag rid: 'SV-79723r1_rule'
  tag stig_id: 'WSDP-AG-000049'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-71173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

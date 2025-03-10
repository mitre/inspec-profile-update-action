control 'SV-68897' do
  title 'The ALG must reveal error messages only to the ISSO, ISSM, and SCA.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can give configuration details about the network element.

Limiting access to system logs and administrative consoles to authorized personnel will help to mitigate this risk. However, user feedback and error messages should also be restricted by type and content in accordance with security best practices (e.g., ICMP messages)."
  desc 'check', 'Verify the ALG reveals error messages only to the ISSO, ISSM, and SCA.

If the ALG does not reveal error messages only to the ISSO, ISSM, and SCA, this is a finding.'
  desc 'fix', 'Configure the ALG to reveal error messages only to the ISSO, ISSM, and SCA.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55271r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54651'
  tag rid: 'SV-68897r1_rule'
  tag stig_id: 'SRG-NET-000402-ALG-000130'
  tag gtitle: 'SRG-NET-000402-ALG-000130'
  tag fix_id: 'F-59507r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

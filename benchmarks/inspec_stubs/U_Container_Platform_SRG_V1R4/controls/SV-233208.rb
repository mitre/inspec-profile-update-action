control 'SV-233208' do
  title 'The container platform must configure web management tools and Application Program Interfaces (API) with FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network.'
  desc 'check', 'Validate the container platform web management tools and Application Program Interfaces (API) are configured to use FIPS-validated Advanced Encryption Standard (AES) cipher block algorithms to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions. 

If the web management tools and API are not configured to use FIPS-validated Advanced Encryption Standard (AES) cipher block algorithms, this is a finding.'
  desc 'fix', 'Configure the container platform web management tools and Application Program Interfaces (API) with FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36144r855392_chk'
  tag severity: 'medium'
  tag gid: 'V-233208'
  tag rid: 'SV-233208r879785_rule'
  tag stig_id: 'SRG-APP-000412-CTR-001000'
  tag gtitle: 'SRG-APP-000412'
  tag fix_id: 'F-36112r878094_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end

control 'SV-235999' do
  title 'Oracle WebLogic must be integrated with a tool to implement multi-factor user authentication.'
  desc 'Multifactor authentication is defined as: using two or more factors to achieve authentication. 

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). A CAC meets this definition.

Implementing a tool, such as Oracle Access Manager, will implement multi-factor authentication to the application server and tie the authenticated user to a user account (i.e. roles and privileges) assigned to the authenticated user.'
  desc 'check', 'Review the WebLogic configuration to determine if a tool, such as Oracle Access Manager, is in place to implement multi-factor authentication for the users. If a tool is not in place to implement multi-factor authentication, this is a finding.'
  desc 'fix', 'Install a tool, such as Oracle Access Manager, to handle multi-factor authentication of users.'
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39218r628773_chk'
  tag severity: 'medium'
  tag gid: 'V-235999'
  tag rid: 'SV-235999r628775_rule'
  tag stig_id: 'WBLC-10-000272'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39181r628774_fix'
  tag 'documentable'
  tag legacy: ['SV-70641', 'V-56387']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

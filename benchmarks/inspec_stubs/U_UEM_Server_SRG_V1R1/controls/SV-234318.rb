control 'SV-234318' do
  title 'The UEM server must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual). 

Non-repudiation services can be used to determine if information originated from a particular individual, or if an individual took specific actions (e.g., sending an email, signing a contract, approving a procurement request) or received specific information. Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. The application will be configured to provide non-repudiation services for an organization-defined set of commands that are used by the user (or processes action on behalf of the user).

DoD PKI provides for non-repudiation through the use of digital signatures. Non-repudiation requirements will vary from one application to another and will be defined based on application functionality, data sensitivity, and mission requirements. 

Satisfies:FCS_COP.1.1(3), FCS_COP.1.1(4)'
  desc 'check', 'Verify the UEM server protects against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

If the UEM server does not protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation this is a finding.'
  desc 'fix', 'Configure the UEM server to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37503r613964_chk'
  tag severity: 'medium'
  tag gid: 'V-234318'
  tag rid: 'SV-234318r617355_rule'
  tag stig_id: 'SRG-APP-000080-UEM-000044'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-37468r613965_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end

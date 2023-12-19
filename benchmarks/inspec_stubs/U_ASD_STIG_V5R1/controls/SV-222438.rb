control 'SV-222438' do
  title 'The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual).

Non-repudiation services can be used to determine if information originated from a particular individual, or if an individual took specific actions (e.g., sending an email, signing a contract, approving a procurement request) or received specific information. Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. The application will be configured to provide non-repudiation services for an organization-defined set of commands that are used by the user (or processes action on behalf of the user).

DoD PKI provides for non-repudiation through the use of digital signatures. Non-repudiation requirements will vary from one application to another and will be defined based on application functionality, data sensitivity, and mission requirements.'
  desc 'check', 'Review the application documentation, the design requirements if available and interview the application administrator.

Identify application services or application commands that are formerly required and designed to provide non-repudiation services (e.g., digital signatures).  

If the application documentation specifically states that non-repudiation services for application users are not defined as part of the application design, this requirement is not applicable.  

Email is one example of an application specifically required to provide non-repudiation services for application users within the DoD. 

Interview the application administrators and have them describe which aspect of the application, if any, is required to provide digital signatures.

Access the application as a test user or observe the application administrator as they demonstrate the applications signature capabilities.

If the application is required to provide non-repudiation services and does not, or if the non-repudiation functionality fails on demonstration, this is a finding.'
  desc 'fix', 'Configure the application to provide users with a non-repudiation function in the form of digital signatures when it is required by the organization or by the application design and architecture.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24108r493222_chk'
  tag severity: 'medium'
  tag gid: 'V-222438'
  tag rid: 'SV-222438r508029_rule'
  tag stig_id: 'APSC-DV-000590'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-24097r493223_fix'
  tag 'documentable'
  tag legacy: ['SV-83979', 'V-69357']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end

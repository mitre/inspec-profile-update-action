control 'SV-205457' do
  title 'The Mainframe Product must protect against an individual (or process acting on behalf of an individual) falsely denying having performed actions defined in the site security plan to be covered by non-repudiation.'
  desc 'Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual).

Non-repudiation services can be used to determine if information originated from a particular individual, or if an individual took specific actions (e.g., sending an email, signing a contract, approving a procurement request) or received specific information. Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. The application will be configured to provide non-repudiation services for an organization-defined set of commands that are used by the user (or processes action on behalf of the user).

DoD PKI provides for non-repudiation through the use of digital signatures. Non-repudiation requirements will vary from one application to another and will be defined based on application functionality, data sensitivity and mission requirements.'
  desc 'check', 'If the Mainframe Product does not perform tasks on the behalf of other users, this is not applicable.

Examine configuration settings.

Determine whether settings identify initiating user for authentication. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to identify initiating user for authentication for all tasks.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5723r299604_chk'
  tag severity: 'medium'
  tag gid: 'V-205457'
  tag rid: 'SV-205457r395691_rule'
  tag stig_id: 'SRG-APP-000080-MFP-000102'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-5723r299605_fix'
  tag 'documentable'
  tag legacy: ['SV-82669', 'V-68179']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end

control 'SV-204715' do
  title 'The application server must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'Non-repudiation of actions taken is required in order to maintain application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Typical application server actions requiring non-repudiation will be related to application deployment among developers/users and administrative actions taken by admin personnel.'
  desc 'check', "Review application server product documentation and server configuration to determine if the system does protect against an individual's (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

If the application does not meet this requirement, this is a finding."
  desc 'fix', "Configure the application server to protect against an individual's (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation."
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4835r282792_chk'
  tag severity: 'medium'
  tag gid: 'V-204715'
  tag rid: 'SV-204715r879554_rule'
  tag stig_id: 'SRG-APP-000080-AS-000045'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-4835r282793_fix'
  tag 'documentable'
  tag legacy: ['SV-46422', 'V-35135']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end

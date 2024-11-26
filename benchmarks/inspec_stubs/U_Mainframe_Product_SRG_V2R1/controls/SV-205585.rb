control 'SV-205585' do
  title 'The Mainframe Product must implement cryptographic mechanisms to prevent unauthorized disclosure of all information not cleared for public release at rest on system components outside of organization facilities.'
  desc 'Applications handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the confidentiality of organizational information. The strength of mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Examine installation and configuration settings.

Review requirements for relevant organization or site-defined information.

If the Mainframe Product does not have cryptographic mechanisms implemented to prevent unauthorized disclosure of all information not cleared for public release at rest on system components outside of organization facilities, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to implement cryptographic mechanisms to prevent unauthorized disclosure of all information not cleared for public release at rest on system components outside of organization facilities.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5851r299982_chk'
  tag severity: 'medium'
  tag gid: 'V-205585'
  tag rid: 'SV-205585r851349_rule'
  tag stig_id: 'SRG-APP-000429-MFP-000304'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-5851r299983_fix'
  tag 'documentable'
  tag legacy: ['SV-82957', 'V-68467']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end

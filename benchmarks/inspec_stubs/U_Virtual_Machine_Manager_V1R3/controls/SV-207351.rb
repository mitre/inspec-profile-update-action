control 'SV-207351' do
  title 'The VMM must use DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public VMMs by an authorized user (or another VMM) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.'
  desc 'check', 'Verify the VMM uses DoD-approved encryption to protect the confidentiality of remote access sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use DoD-approved encryption to protect the confidentiality of remote access sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7608r365463_chk'
  tag severity: 'medium'
  tag gid: 'V-207351'
  tag rid: 'SV-207351r378610_rule'
  tag stig_id: 'SRG-OS-000033-VMM-000140'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-7608r365464_fix'
  tag 'documentable'
  tag legacy: ['SV-71133', 'V-56873']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

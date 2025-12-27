control 'SV-203603' do
  title 'The operating system must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.'
  desc 'check', 'Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  impact 0.7
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3728r557065_chk'
  tag severity: 'high'
  tag gid: 'V-203603'
  tag rid: 'SV-203603r877398_rule'
  tag stig_id: 'SRG-OS-000033-GPOS-00014'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-3728r557066_fix'
  tag 'documentable'
  tag legacy: ['V-56641', 'SV-70901']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

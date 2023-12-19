control 'SV-237906' do
  title 'The IBM z/VM TCP/IP configuration must include an SSLSERVERID statement.'
  desc 'The Secure Socket Layer (SSL) server, provides processing support for secure (encrypted) communication between remote clients and z/VM TCP/IP application servers that are configured for secure communications The TCP/IP (stack) server routes requests for secure connections to an SSL server, which interacts with a client on behalf of an application server to perform handshake operations and the exchange of cryptographic parameters for a secure session. The SSL server then manages the encryption and decryption of data for an established, secure session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

'
  desc 'check', 'Examine the "SSLSERVERID" statement in the TCP/IP server configuration file.

If the "SSLSERVERID" statement identifies at least one userID for an SSL server, this is not a finding.'
  desc 'fix', 'Configure the "SSLSERVERID" statement to force auto logging of an SSL server before all other servers in the "AUTOLOG" list.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41116r858943_chk'
  tag severity: 'medium'
  tag gid: 'V-237906'
  tag rid: 'SV-237906r858945_rule'
  tag stig_id: 'IBMZ-VM-000110'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-41075r858944_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000423-GPOS-00187']
  tag 'documentable'
  tag legacy: ['SV-93565', 'V-78859']
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-002448', 'CCI-002451', 'CCI-002452', 'CCI-002920', 'CCI-003153']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'SC-12 (3)', 'SC-15 (3)', 'SC-15 (4)', 'PE-3 c', 'SA-9 (5)']
end

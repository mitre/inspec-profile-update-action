control 'SV-207245' do
  title 'The VPN Gateway and Client must be configured to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered.

This requirement also applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

For example, configure all ISAKMP policies to use AES for Internet Key Exchange (IKE) cryptographic encryption operations and SHA-2 to protect data integrity.'
  desc 'check', 'Verify the VPN Gateway and the remote access client are configured to protect the confidentiality and integrity of transmitted information.

If VPN Gateway and Client does not protect the confidentiality and integrity of transmitted information, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway and the remote access client to protect the confidentiality and integrity of transmitted information.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7505r378356_chk'
  tag severity: 'high'
  tag gid: 'V-207245'
  tag rid: 'SV-207245r803432_rule'
  tag stig_id: 'SRG-NET-000371-VPN-001650'
  tag gtitle: 'SRG-NET-000371'
  tag fix_id: 'F-7505r378357_fix'
  tag 'documentable'
  tag legacy: ['V-97185', 'SV-106323']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

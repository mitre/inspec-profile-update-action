control 'SV-70995' do
  title 'The operating system must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Verify the operating system protects the confidentiality and integrity of transmitted information. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect the confidentiality and integrity of transmitted information.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57305r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56735'
  tag rid: 'SV-70995r1_rule'
  tag stig_id: 'SRG-OS-000423-GPOS-00187'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-61631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

control 'SV-207499' do
  title 'The VMM must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of VMM components from which information can be transmitted (e.g., guest VMs, servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Verify the VMM protects the confidentiality and integrity of transmitted information.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect the confidentiality and integrity of transmitted information.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7756r365901_chk'
  tag severity: 'medium'
  tag gid: 'V-207499'
  tag rid: 'SV-207499r854673_rule'
  tag stig_id: 'SRG-OS-000423-VMM-001700'
  tag gtitle: 'SRG-OS-000423'
  tag fix_id: 'F-7756r365902_fix'
  tag 'documentable'
  tag legacy: ['V-57299', 'SV-71559']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

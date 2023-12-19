control 'SV-207471' do
  title 'The VMM must audit the enforcement actions used to restrict access associated with changes to the system.'
  desc 'Without auditing the enforcement of access restrictions against changes to the VMM configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Verify the VMM audits the enforcement actions used to restrict access associated with changes to the system.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to audit the enforcement actions used to restrict access associated with changes to the system.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7728r365817_chk'
  tag severity: 'medium'
  tag gid: 'V-207471'
  tag rid: 'SV-207471r854644_rule'
  tag stig_id: 'SRG-OS-000365-VMM-001420'
  tag gtitle: 'SRG-OS-000365'
  tag fix_id: 'F-7728r365818_fix'
  tag 'documentable'
  tag legacy: ['V-57143', 'SV-71403']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

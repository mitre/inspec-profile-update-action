control 'SV-71111' do
  title 'The operating system must audit the enforcement actions used to restrict access associated with changes to the system.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Verify the operating system audits the enforcement actions used to restrict access associated with changes to the system. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to audit the enforcement actions used to restrict access associated with changes to the system.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57421r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56851'
  tag rid: 'SV-71111r1_rule'
  tag stig_id: 'SRG-OS-000365-GPOS-00152'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-61747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

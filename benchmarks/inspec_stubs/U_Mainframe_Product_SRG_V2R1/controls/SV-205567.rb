control 'SV-205567' do
  title 'The Mainframe Product must audit the enforcement actions used to restrict access associated with changes to the application.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Examine Configuration settings.

Examine organization change management policies.

If the Mainframe Product does not audit the enforcement actions used to access restriction associated with changes to the application in accordance with change management policies using System Management Facility (SMF) or an external security manager audit, this is a finding.'
  desc 'fix', 'Configure Mainframe Product change management settings to audit the enforcement actions used to restrict access associated with changes to application configuration to appropriate users according to organizational change policies.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5833r299928_chk'
  tag severity: 'medium'
  tag gid: 'V-205567'
  tag rid: 'SV-205567r851333_rule'
  tag stig_id: 'SRG-APP-000381-MFP-000188'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-5833r299929_fix'
  tag 'documentable'
  tag legacy: ['SV-82801', 'V-68311']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

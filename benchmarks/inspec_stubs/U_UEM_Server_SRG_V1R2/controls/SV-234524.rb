control 'SV-234524' do
  title 'The UEM server must audit the enforcement actions used to restrict access associated with changes to the application.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server audits the enforcement actions used to restrict access associated with changes to the application.

If the UEM server does not audit the enforcement actions used to restrict access associated with changes to the application, this is a finding.'
  desc 'fix', 'Configure the UEM server to audit the enforcement actions used to restrict access associated with changes to the application.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37709r851593_chk'
  tag severity: 'medium'
  tag gid: 'V-234524'
  tag rid: 'SV-234524r879754_rule'
  tag stig_id: 'SRG-APP-000381-UEM-000252'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-37674r615216_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

control 'SV-202107' do
  title 'The network device must audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Determine if the network device audits the enforcement actions used to restrict access associated with changes to the device. This requirement may be verified by demonstration, configuration review or validated test results.

If the network device does not audit the enforcement actions used to restrict access associated with changes to the device, this is a finding.'
  desc 'fix', 'Configure the network device to audit the enforcement actions used to restrict access associated with changes to the device.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2233r381950_chk'
  tag severity: 'medium'
  tag gid: 'V-202107'
  tag rid: 'SV-202107r400009_rule'
  tag stig_id: 'SRG-APP-000381-NDM-000305'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-2234r381951_fix'
  tag 'documentable'
  tag legacy: ['SV-69491', 'V-55245']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

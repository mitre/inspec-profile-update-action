control 'SV-79651' do
  title 'The DataPower Gateway must audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Confirm that the Audit log administrative state is "up". Using the web interface, go to Object >> Logging Configuration >> Audit Log Settings. Confirm that the Audit Level is set to Full. If it is not, this is a finding.'
  desc 'fix', 'Configure the DataPower Gateway to log all enforcement action audit events to an external log target. 

Using the web interface, go to Objects >> Logging Configuration >> Log Target. Add an audit log target. View the Event Subscriptions tab to set audit log subscription Event Priority level.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65161'
  tag rid: 'SV-79651r1_rule'
  tag stig_id: 'WSDP-NM-000107'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-71101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

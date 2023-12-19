control 'SV-80473' do
  title 'Trend Deep Security must audit the enforcement actions used to restrict access associated with changes to the application.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the enforcement actions used to restrict access associated with changes to the application are audited.

System Events include changes to the configuration of an Agent/Appliance, the Deep Security Manager, or Users. They also include errors that may occur during normal operation of the Trend Deep Security system. 

To ensure the necessary events are captured, verify the Administration >> System Settings >> System Events, against the local policy established by the ISSO. 

If the settings configured do not match local policy, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to audit the enforcement actions used to restrict access associated with changes to the application.

To configure the application to captured the events identified by the ISSO, go to the Administration >> System Settings >> System Events tab.

Enable all applicable policies with “Record” and “Forward.”'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65983'
  tag rid: 'SV-80473r1_rule'
  tag stig_id: 'TMDS-00-000300'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-72059r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end

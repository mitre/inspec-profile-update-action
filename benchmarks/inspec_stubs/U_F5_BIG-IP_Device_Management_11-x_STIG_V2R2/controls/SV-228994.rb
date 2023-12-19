control 'SV-228994' do
  title 'The BIG-IP appliance must be configured to activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in an unsecure state. If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur that could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the network device must activate a system alert message, send an alarm, or shut down."
  desc 'check', 'Verify the BIG-IP appliance is configured to activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected. 

Navigate to the BIG-IP System manager >> Logs >> Configuration >> Options.

Verify that "MCP" under the "Audit Logging" section is set to Debug.

Navigate to the BIG-IP System manager >> System >> High Availability >> Fail-Safe >> System.

Verify "Switch Board Failure" under the "System Trigger Properties" section is set to perform the appropriate action based on the location of the device. 

If the BIG-IP appliance is not configured to activate a system alert message, send an alarm, or automatically shut down when a component failure is detected, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31309r518027_chk'
  tag severity: 'medium'
  tag gid: 'V-228994'
  tag rid: 'SV-228994r879887_rule'
  tag stig_id: 'F5BI-DM-000153'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31286r518028_fix'
  tag 'documentable'
  tag legacy: ['V-60175', 'SV-74605']
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end

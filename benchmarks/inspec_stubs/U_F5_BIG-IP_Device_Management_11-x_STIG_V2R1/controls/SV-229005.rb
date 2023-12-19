control 'SV-229005' do
  title 'The BIG-IP appliance must be configured to generate an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. This could lead to the loss of audit information. Note that while the network device must generate the alert, notification may be done by a management server.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured syslog server that generates an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Remote Logging.

Verify a syslog destination is configured that generates an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

If an immediate alert is not generated when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured syslog server to generate an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31320r518059_chk'
  tag severity: 'low'
  tag gid: 'V-229005'
  tag rid: 'SV-229005r557520_rule'
  tag stig_id: 'F5BI-DM-000193'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31297r518060_fix'
  tag 'documentable'
  tag legacy: ['SV-74633', 'V-60203']
  tag cci: ['CCI-000366', 'CCI-001855']
  tag nist: ['CM-6 b', 'AU-5 (1)']
end

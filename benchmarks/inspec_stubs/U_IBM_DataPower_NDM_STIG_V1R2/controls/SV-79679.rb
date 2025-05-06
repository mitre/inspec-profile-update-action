control 'SV-79679' do
  title 'The DataPower Gateway must not use 0.0.0.0 as the management IP address.'
  desc 'If 0.0.0.0 as the management IP address, the DataPower appliance will listen on all configured interfaces for management traffic. This can allow an attacker to gain privileged-level access from an untrusted network.'
  desc 'check', 'Using an administrator account, log on to the default domain of the appliance.

Navigate to Network >> Management >> Web Management Service.

View the Local Address field; if the value is “0.0.0.0”, this is a finding.'
  desc 'fix', 'To configure the DataPower appliance for web management:

Using an administrator account, log on to the default domain of the appliance.

On the Configure Web Management Service screen, complete the required information.

Set the Administrative state to “enabled”.

For the Local Address, use the IP address from the management subnet assigned to the unit.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65189'
  tag rid: 'SV-79679r1_rule'
  tag stig_id: 'WSDP-NM-000143'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-71129r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end

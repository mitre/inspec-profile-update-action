control 'SV-254863' do
  title 'The Tanium operating system (TanOS) must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "5" for "SNMP Configuration," and then press "Enter".

If the State is "Disabled" this is a finding.

If the state is "Enabled", work with the SNMP monitoring system administrator to ensure warnings are sent when TanOS storage reaches 75 percent of capacity. If they are not being sent, and this is a finding.'
  desc 'fix', '1. Access the TanOS interactively.

2. Press "A" for "Appliance Configuration Menu," and then press "Enter".

3. Press "5" for "SNMP Configuration," and then press "Enter".

4. Press "S" for "Set Password and Start the SNMP Service," and then press "Enter".

5. Enter the desired SNMP password and press "Enter".

6. Press "Enter" to continue and return to the SNMP configuration menu and verify the state is now "Enabled".

Work with the SNMP monitoring system administrator to enable warning alerts for low free space.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58476r866128_chk'
  tag severity: 'medium'
  tag gid: 'V-254863'
  tag rid: 'SV-254863r866130_rule'
  tag stig_id: 'TANS-OS-001035'
  tag gtitle: 'SRG-OS-000343'
  tag fix_id: 'F-58420r866129_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end

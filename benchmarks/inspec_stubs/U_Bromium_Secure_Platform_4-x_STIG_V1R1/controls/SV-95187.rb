control 'SV-95187' do
  title 'The Bromium Enterprise Controller (BEC) must forward an event to the central log server when isolation is disabled on any protected Bromium vSentry client.'
  desc 'Disabling isolation on the endpoint is a potential indicator of compromise of insider threat. In production deployments, the ability to disable Bromium isolation is not available to non-privileged users.'
  desc 'check', 'Verify that a syslog destination is configured on the BEC server. 

1. From the management console, click on the selection arrow next to "Events".
2. Click on "Destinations".
3. Inspect the list of configured syslog destinations.
4. Verify that the Severity level for the source Isolation Host is minimally set to "Warning".

If the Bromium monitoring module installed on the BEC or Bromium vSentry does not generate an event and forward to the events server when anomalies in the operation of the application are discovered, this is a finding.'
  desc 'fix', 'Configure the BEC server to automatically forward events to the desired syslog destination.

1. From the management console, click on the selection arrow next to "Events".
2. Click on "Destinations".
3. Click on "Add Syslog Destination".
4. Configure syslog server parameters and verify that the Severity level for the source Isolation Host is minimally set to "Warning".
5. Click "Save".

Additional syslog destinations may be configured for forwarding events to multiple destinations simultaneously.'
  impact 0.7
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80155r1_chk'
  tag severity: 'high'
  tag gid: 'V-80479'
  tag rid: 'SV-95187r1_rule'
  tag stig_id: 'BROM-00-001305'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-87289r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

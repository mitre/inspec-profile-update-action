control 'SV-79795' do
  title 'The DataPower Gateway providing user access control intermediary services must provide the capability for authorized users to capture, record, and log all content related to a selected user session.'
  desc 'Without the capability to capture, record, and log content related to a user session, investigations into suspicious user activity would be hampered.

The intent of this requirement is to ensure the capability to select specific sessions to capture is available in order to support general auditing/incident investigation, or to validate suspected misuse by a specific user. Examples of session events that may be captured include, port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'From the WebGUI Control Panel, click on Troubleshooting >> Click on the Debug Probe tab. Verify that the desired service type and service instance has an active Probe track transaction information for that service instance.

From the WebGUI, go to Objects >> Logging Configuration>> Log Target. Verify the desired filters, triggers, subscriptions, and log destination.

If these items have not been configured, this is a finding.'
  desc 'fix', 'From the WebGUI Control Panel, click on Troubleshooting >> Click on the Debug Probe tab >> Select a desired service type and service instance >> Click on Add Probe to begin tracking transaction information for that service instance.

From the WebGUI, go to Objects >> Logging Configuration >> Log Target. Configure the desired filters, triggers, subscriptions, and log destination.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65305'
  tag rid: 'SV-79795r1_rule'
  tag stig_id: 'WSDP-AG-000120'
  tag gtitle: 'SRG-NET-000399-ALG-000042'
  tag fix_id: 'F-71245r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end

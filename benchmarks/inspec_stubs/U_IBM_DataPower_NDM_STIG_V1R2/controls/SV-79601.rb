control 'SV-79601' do
  title 'The DataPower Gateway must activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in an insecure state. If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur which could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the network device must activate a system alert message, send an alarm, or shut down."
  desc 'check', 'From the DataPower command line, enter "failure-notification", then enter "show failure-notification". If it is "disabled", this is a finding. This capability is enabled by default.'
  desc 'fix', 'From the DataPower command line, enter "failure-notification" to configure DataPower to generate failure notifications. 

With failure notification enabled, you can send an error report to a designated recipient or upload to a specific location after the appliance returns to service from an unscheduled outage. 

This error report can contain diagnostic details. Intrusion detection will provide a warning and restart in Fail-Safe mode.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65111'
  tag rid: 'SV-79601r1_rule'
  tag stig_id: 'WSDP-NM-000076'
  tag gtitle: 'SRG-APP-000268-NDM-000274'
  tag fix_id: 'F-71051r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end

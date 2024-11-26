control 'SV-79729' do
  title 'In the event of a system failure of the DataPower Gateway function, the DataPower Gateway must save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.'
  desc 'Failure in a secure state can address safety or security in accordance with the mission needs of the organization. Failure to a secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving state information helps to facilitate the restart of the ALG application and a return to the operational mode with less disruption.

This requirement applies to a failure of the ALG function rather than the device or operating system as a whole which is addressed in the Network Device Management SRG.

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Verify that all desired optional failure notification functions are configured by going to the WebGUI at Administration >> Device >> Failure Notification. 

If this is not configured, this is a finding.'
  desc 'fix', 'By default, the DataPower Gateway, in the event of a system failure, saves diagnostic information, logs system messages, and loads the most current security policies, rules, and signatures when restarted and reverts to Failsafe Mode

In addition, the DataPower Gateway supports the configuration of optional failure notification functions. These include the following: upload error report, include internal state, background packet capture, background log capture, and background memory trace. 

To configure these additional functions, use the WebGUI at Administration >> Device >> Failure Notification. Select the capabilities desired.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65239'
  tag rid: 'SV-79729r1_rule'
  tag stig_id: 'WSDP-AG-000054'
  tag gtitle: 'SRG-NET-000236-ALG-000119'
  tag fix_id: 'F-71179r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end

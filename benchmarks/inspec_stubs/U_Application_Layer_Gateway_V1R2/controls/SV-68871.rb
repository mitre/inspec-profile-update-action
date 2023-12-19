control 'SV-68871' do
  title 'In the event of a system failure of the ALG function, the ALG must save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.'
  desc 'Failure in a secure state can address safety or security in accordance with the mission needs of the organization. Failure to a secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving state information helps to facilitate the restart of the ALG application and a return to the operational mode with less disruption.

This requirement applies to a failure of the ALG function rather than the device or operating system as a whole which is addressed in the Network Device Management SRG.

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Verify the ALG, in the event of a system failure, saves diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.

If the ALG does not save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted, this is a finding.'
  desc 'fix', 'Configure the ALG, in the event of a system failure, to save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55245r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54625'
  tag rid: 'SV-68871r1_rule'
  tag stig_id: 'SRG-NET-000236-ALG-000119'
  tag gtitle: 'SRG-NET-000236-ALG-000119'
  tag fix_id: 'F-59481r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end

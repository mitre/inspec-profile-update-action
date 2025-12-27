control 'SV-45660' do
  title 'In the event of a failure of the IDPS function, the IDPS must save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.'
  desc 'Failure in a secure state address safety or security in accordance with the mission needs of the organization. Failure to a secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving state information helps to facilitate the restart of the IDPS application and a return to operation with minimum disruption.

This requirement applies to a failure of the IDPS function rather than the device or operating system as a whole which is addressed in the Network Device Management SRG.

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Verify the IDPS, upon failure of the IDPS function, saves diagnostic information, logs system messages, and loads the most current security policies, rules, and signatures when restarted.

If IDPS function, upon system failure, does not save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted, this is a finding.'
  desc 'fix', 'Configure the IDPS to, upon failure of the IDPS function, save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-43026r3_chk'
  tag severity: 'medium'
  tag gid: 'V-34750'
  tag rid: 'SV-45660r2_rule'
  tag stig_id: 'SRG-NET-000236-IDPS-00170'
  tag gtitle: 'SRG-NET-000236-IDPS-00170'
  tag fix_id: 'F-39058r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end

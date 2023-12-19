control 'SV-206698' do
  title 'In the event of a system failure of the firewall function, the firewall must be configured to save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted.'
  desc 'Failure to a secure state can address safety or security in accordance with the mission needs of the organization. Failure to a secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving state information helps to facilitate the restart of the firewall application and a return to the operational mode with less disruption.

This requirement applies to a failure of the firewall function rather than the device or operating system as a whole, which is addressed in the Network Device Management SRG.

Since it is usually not possible to test this functionality in a production environment, systems should be validated either in a testing environment or prior to installation. This requirement is usually a function of the design of the firewall. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'View the firewall failover configuration or system documentation.

Verify that in the event of a system failure of the firewall function, the firewall saves diagnostic information, logs system messages, and loads the most current security policies, rules, and signatures. Testing of this functionality in a production environment is not recommended.

If in the event of a system failure of the firewall function the firewall does not save diagnostic information, log system messages, and load the most current security policies, rules, and signatures when restarted, this is a finding.'
  desc 'fix', 'Configure the firewall to fail securely in the event of a transiently corrupt state or failure condition.

When the system restarts, the system boot process must not succeed without passing all self-tests for cryptographic algorithms, RNG tests, and software integrity tests.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6955r297873_chk'
  tag severity: 'medium'
  tag gid: 'V-206698'
  tag rid: 'SV-206698r604133_rule'
  tag stig_id: 'SRG-NET-000236-FW-000027'
  tag gtitle: 'SRG-NET-000236'
  tag fix_id: 'F-6955r297874_fix'
  tag 'documentable'
  tag legacy: ['SV-94171', 'V-79465']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end

control 'SV-30532' do
  title 'System shutdown procedures documentation must exist for each partition defined to the system.'
  desc 'If procedures for performing system shutdowns are not in place, it is extremely difficult to ensure overall data and operating system integrity.'
  desc 'check', 'Have the System Administrator validate that System Shutdown Documentation exists for all partitions that are defined on the system. 

a)	Using the Hardware Management Console, do the following:

1)	Access CPC Images Group displays.  (This will list the LPARs.)

2)	Compare the partition names listed on the Partition Page to validate that System Shutdown procedures exist for each entered on the Central Processor Complex Domain/LPAR Names.  

	If System Shutdown Procedures do not exist for each partition, this is a FINDING.'
  desc 'fix', 'Create or refine procedures for performing system shutdowns for each partition.'
  impact 0.3
  ref 'DPMS Target IBM HMC LIC Policy'
  tag check_id: 'C-30870r1_chk'
  tag severity: 'low'
  tag gid: 'V-24843'
  tag rid: 'SV-30532r1_rule'
  tag stig_id: 'HMCP0120'
  tag gtitle: 'HMCP0120'
  tag fix_id: 'F-27490r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'COTR-1'
  tag cci: ['CCI-000904']
  tag nist: ['PE-1 a 1 (a)']
end

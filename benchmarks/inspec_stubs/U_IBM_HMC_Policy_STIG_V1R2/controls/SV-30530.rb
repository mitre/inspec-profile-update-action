control 'SV-30530' do
  title 'Initial Program Load (IPL) Procedures must exists for each partition defined to the system.'
  desc 'If procedures for performing IPLs are not in place, it is extremely difficult to ensure overall operating system integrity.'
  desc 'check', 'Have the Systems Administrator validate that IPL Procedures Documentation exists for all partitions that are defined on the system. 

Using the Hardware Management Console, do the following:

1)	Access CPC Images Group displays.  (This will list the LPARs.)

2)	Compare the partition names listed on the Partition Page to validate that IPL procedures exist for each entered on the Central Processor Complex Domain/LPAR Names.  

	If IPL Procedures do not exist for each partition, this is a FINDING.'
  desc 'fix', 'Create or refine procedures for performing IPLs for the LPARs/partitions defined on the system.'
  impact 0.3
  ref 'DPMS Target IBM HMC LIC Policy'
  tag check_id: 'C-30867r1_chk'
  tag severity: 'low'
  tag gid: 'V-24841'
  tag rid: 'SV-30530r1_rule'
  tag stig_id: 'HMCP0010'
  tag gtitle: 'HMCP0010'
  tag fix_id: 'F-27488r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'COTR-1'
  tag cci: ['CCI-000904']
  tag nist: ['PE-1 a 1 (a)']
end

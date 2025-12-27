control 'SV-256853' do
  title 'Initial Program Load (IPL) Procedures must exists for each partition defined to the system.'
  desc 'If procedures for performing IPLs are not in place, it is extremely difficult to ensure overall operating system integrity.'
  desc 'check', 'Have the Systems Administrator validate that IPL Procedures Documentation exists for all partitions that are defined on the system. 

Using the Hardware Management Console, do the following:

1)	Access CPC Images Group displays.  (This will list the LPARs.)

2)	Compare the partition names listed on the Partition Page to validate that IPL procedures exist for each entered on the Central Processor Complex Domain/LPAR Names.  

	If IPL Procedures do not exist for each partition, this is a FINDING.'
  desc 'fix', 'Create or refine procedures for performing IPLs for the LPARs/partitions defined on the system.'
  impact 0.3
  ref 'DPMS Target IBM Hardware Management Console (HMC) Policies'
  tag check_id: 'C-60528r890903_chk'
  tag severity: 'low'
  tag gid: 'V-256853'
  tag rid: 'SV-256853r890905_rule'
  tag stig_id: 'HMCP0010'
  tag gtitle: 'SRG-OS-000360-GPOS-00147'
  tag fix_id: 'F-60471r890904_fix'
  tag 'documentable'
  tag legacy: ['V-24841', 'SV-30530']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

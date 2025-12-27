control 'SV-256855' do
  title 'System shutdown procedures documentation must exist for each partition defined to the system.'
  desc 'If procedures for performing system shutdowns are not in place, it is extremely difficult to ensure overall data and operating system integrity.'
  desc 'check', 'Have the System Administrator validate that System Shutdown Documentation exists for all partitions that are defined on the system. 

a)	Using the Hardware Management Console, do the following:

1)	Access CPC Images Group displays.  (This will list the LPARs.)

2)	Compare the partition names listed on the Partition Page to validate that System Shutdown procedures exist for each entered on the Central Processor Complex Domain/LPAR Names.  

	If System Shutdown Procedures do not exist for each partition, this is a FINDING.'
  desc 'fix', 'Create or refine procedures for performing system shutdowns for each partition.'
  impact 0.3
  ref 'DPMS Target IBM Hardware Management Console (HMC) Policies'
  tag check_id: 'C-60530r890909_chk'
  tag severity: 'low'
  tag gid: 'V-256855'
  tag rid: 'SV-256855r890911_rule'
  tag stig_id: 'HMCP0120'
  tag gtitle: 'SRG-OS-000360-GPOS-00147'
  tag fix_id: 'F-60473r890910_fix'
  tag 'documentable'
  tag legacy: ['V-24843', 'SV-30532']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

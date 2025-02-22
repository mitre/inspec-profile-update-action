control 'SV-30052' do
  title 'Unauthorized partitions must not exist on the system complex.'
  desc 'The running of unauthorized Logical Partitions (LPARs) could allow a “Trojan horse” version of the operating environment to be introduced into the system complex. This could impact the integrity of the system complex and the confidentiality of the data that resides in it.'
  desc 'check', 'Using the Hardware Management Console, do the following:

Access the Change LPAR Control Panel. (This will list the LPARs.)

Compare the partition names listed on the Partition Page to the names entered on the Central Processor Complex Domain/LPAR Names table.  
Note: Each site should maintain a list of valid LPARS that are configured on thier system , what operating system, and the purpose of each LPAR.
If unauthorized partitions exist on the system complex and the deviation is not documented, this is a FINDING.'
  desc 'fix', 'Review the LPARs on the system and remove any unauthorized LPARs. If a deviation exists, the system administrator will provide written justification for the deviation.

This will be displayed by using the Change LPAR Control Panel.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-2925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24378'
  tag rid: 'SV-30052r2_rule'
  tag stig_id: 'HLP0010'
  tag gtitle: 'HLP0010'
  tag fix_id: 'F-2345r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002101']
  tag nist: ['CA-9 (a)']
end

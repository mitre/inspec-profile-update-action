control 'SV-30058' do
  title 'Central processors must be restricted for classified/restricted Logical Partitions (LPARs).'
  desc 'Allowing unrestricted access to classified processors for all LPARs could cause the corruption and loss of classified data sets, which could compromise classified processing.'
  desc 'check', 'Have the system administrator or systems programmer use the Hardware Management Console; to verify that the LPAR processors are dedicated for exclusive use by classified LPARs.  

Use the Processor Page to do this.  The Dedicated Central Processors option must be turned on.

If Central processors are not restricted for classified/restricted LPARs, this is a FINDING.'
  desc 'fix', 'Review the Processor Page under PR/SM and turn on the Dedicated Central Processor option for classified or restricted LPARs.  For unclassified LPARs, this option should not be turned on, unless determined by the site.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-3270r1_chk'
  tag severity: 'high'
  tag gid: 'V-24383'
  tag rid: 'SV-30058r2_rule'
  tag stig_id: 'HLP0060'
  tag gtitle: 'HLP0060'
  tag fix_id: 'F-2350r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

control 'SV-30056' do
  title 'Classified Logical Partition (LPAR) channel paths must be restricted.'
  desc 'Restricted LPAR channel paths are necessary to ensure data integrity. Unrestricted LPAR channel path access could result in a compromise of data integrity. When a classified LPAR exists on a mainframe which requires total isolation, all paths to that LPAR must be restricted.'
  desc 'check', 'Have the System Administrator or Systems Programmer on classified systems use the Hardware Management Console to verify that the LPAR channel paths are reserved from the rest of the LPARs. 

Use the Security Definitions Panel to verify  this.  The Logical Partition Isolation option must be turned on.

If the Classified LPAR channel paths are not restricted then this is a FINDING.'
  desc 'fix', 'Have the System Administrator or Systems Programmer for classified systems use the Hardware Management Console to verify that the LPAR channel paths are reserved from the rest of the LPARs. Use the Security Definitions Panel to verify this. The Logical Partition Isolation option must be turned on for classified systems.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-3268r1_chk'
  tag severity: 'high'
  tag gid: 'V-24381'
  tag rid: 'SV-30056r2_rule'
  tag stig_id: 'HLP0040'
  tag gtitle: 'HLP0040'
  tag fix_id: 'F-2348r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

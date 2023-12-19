control 'SV-251647' do
  title 'The storage used for data collection by CA IDMS web services must be protected.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.

'
  desc 'check', 'Log on to IDMS DC system and issue "DCPROFIL". If SYSTEM STORAGE PROTECTED: display is "NO", this is a finding. 

Issue DCMT D PROGRAM RHDCWSSP. If Storage Prot is "NO", this is a finding.'
  desc 'fix', 'Use the following system generation parameters to enable the use of standard storage protection: 

Set STORAGE KEY parameter of the SYSTEM statement to a value that is not "9". (The value other than 9 is dependent on how the z/OS parm AllowUserKeyCSA is set).

Set PROTECT/NOPROTECT parameter of the SYSTEM statement to "PROTECT".

Set PROTECT/NOPROTECT parameter of the PROGRAM statement to "PROTECT" for RHDCWSSP.

Generate and restart the system.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55082r807806_chk'
  tag severity: 'medium'
  tag gid: 'V-251647'
  tag rid: 'SV-251647r855285_rule'
  tag stig_id: 'IDMS-DB-000830'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-55036r807807_fix'
  tag satisfies: ['SRG-APP-000441-DB-000378', 'SRG-APP-000442-DB-000379']
  tag 'documentable'
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end

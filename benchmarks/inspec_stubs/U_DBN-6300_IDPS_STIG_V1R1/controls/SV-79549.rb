control 'SV-79549' do
  title 'When implemented for discovery protection against unidentified or rogue databases, the DBN-6300 must provide a catalog of all visible databases and database services.'
  desc "If the DBN-6300 is installed incorrectly in the site's network architecture, vulnerable or unknown databases may not be detected and consequently may remain vulnerable and unprotected. 
 
For proper functionality of the DBN-6300, it is necessary to examine the discovered databases to see that an expected wide variety and number of them are covered. If the DBN-6300 is not able to see and detect database services, it will not be able to monitor the databases against threats."
  desc 'check', 'Ask the site representative if the DBN-6300 is used to provide discovery protection against unidentified or rogue databases. 
 
If the DBN-6300 is not used for discovery protection against unidentified or rogue databases, this is not a finding. 
 
Click on the "Database" tab and select the "Database Services" sub-menu. This will reveal all of the currently discovered database services. 
 
If the DBN-6300, which is used to provide protection against unidentified or rogue databases, does not provide a catalog of all visible databases and database services, this is a finding.'
  desc 'fix', 'Configure the system to view databases and database services. 
 
Click on the Database >> Service Discovery tab. 
 
This will reveal all of the currently visible database services that have been seen on the mirrored traffic connection.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65685r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65059'
  tag rid: 'SV-79549r1_rule'
  tag stig_id: 'DBNW-IP-000061'
  tag gtitle: 'SRG-NET-000512-IDPS-00194'
  tag fix_id: 'F-70999r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

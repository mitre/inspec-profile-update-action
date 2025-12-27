control 'SV-222423' do
  title 'Application data protection requirements must be identified and documented.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information. In order to assign the appropriate data protections, application data must be identified and then protection requirements assigned. Access to sensitive data and sensitive data objects should be restricted to those authorized to access the data.

Examples of sensitive data include but are not limited to; Social Security Numbers, Personally Identifiable Information, or any other data that is has been identified as being sensitive in nature by the data owner.

Data storage objects include, for example, databases, database records, and database fields.

Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.

Protection methods include but are not limited to data encryption, Role-Based Access Controls and access authentication.'
  desc 'check', 'Ask the application representative for the documentation that identifies the application data elements, the protection requirements, and any associated steps that are being taken to protect the data.

If the application data protection requirements are not documented, this is a finding.'
  desc 'fix', 'Identify and document the application data elements and the data protection requirements.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24093r493177_chk'
  tag severity: 'medium'
  tag gid: 'V-222423'
  tag rid: 'SV-222423r849427_rule'
  tag stig_id: 'APSC-DV-000440'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-24082r493178_fix'
  tag 'documentable'
  tag legacy: ['SV-83947', 'V-69325']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end

control 'SV-222424' do
  title 'The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data mining occurs when the application is programmatically probed and data is automatically extracted. While there are valid uses for data mining within data sets, the organization should be mindful that adversaries may attempt to use data mining capabilities built into the application in order to completely extract application data so it can be evaluated using methods that are not natively offered by the application. This can provide the adversary with an opportunity to utilize inference attacks or obtain additional insights that might not have been intended when the application was designed.

Methods of extraction include database queries or screen scrapes using the application itself. The entity performing the data mining must have access to the application in order to extract the data. Data mining attacks will usually occur with publicly releasable data access but can also occur when access is limited to authorized or authenticated inside users.

Data storage objects include, for example, databases, database records, and database fields.

Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', 'Review the security plan, application and system documentation and interview the application administrator to identify data mining protections that are required of the application.

If there are no data mining protections required, this requirement is not applicable.

Review the application authentication requirements and permissions.

Review documented protections that have been established to protect from data mining.

This can include limiting the number of queries allowed.

Automated alarming on atypical query events.

Limiting the number of records allowed to be returned in a query.

Not allowing data dumps.

If the application requirements specify protections for data mining and the application administrator is unable to identify or demonstrate that the protections are in place, this is a finding.'
  desc 'fix', 'Utilize and implement data mining protections when requirements specify it.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24094r493180_chk'
  tag severity: 'medium'
  tag gid: 'V-222424'
  tag rid: 'SV-222424r849428_rule'
  tag stig_id: 'APSC-DV-000450'
  tag gtitle: 'SRG-APP-000324'
  tag fix_id: 'F-24083r493181_fix'
  tag 'documentable'
  tag legacy: ['SV-83949', 'V-69327']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end

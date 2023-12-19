control 'SV-233078' do
  title 'The container platform application program interface (API) must uniquely identify and authenticate processes acting on behalf of the users.'
  desc "The container platform API can be used to perform any task within the platform. Often, the API is used to create tasks that perform some kind of maintenance task and run without user interaction. To guarantee the task is authorized, it is important to authenticate the task. These tasks, even though executed without user intervention, run on behalf of a user and must run with the user's authorization. If tasks are allowed to be created without authentication, users could bypass authentication and authorization mechanisms put in place for user interfaces. This could lead to users gaining greater access than given to the user putting the container platform into a compromised state."
  desc 'check', 'Review the container platform API configuration to determine if processes acting on behalf of users are uniquely identified and authenticated. 

If processes acting on behalf of users are not uniquely identified or are not authenticated, this is a finding.'
  desc 'fix', 'Configure the container platform API to uniquely identify and authenticate processes acting on behalf of users.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36014r601708_chk'
  tag severity: 'medium'
  tag gid: 'V-233078'
  tag rid: 'SV-233078r879589_rule'
  tag stig_id: 'SRG-APP-000148-CTR-000350'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-35982r600722_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

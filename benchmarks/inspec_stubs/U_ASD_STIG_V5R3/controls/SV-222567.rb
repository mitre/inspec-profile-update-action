control 'SV-222567' do
  title 'The application must not be vulnerable to race conditions.'
  desc 'A race condition is a timing event within an application that can become a security vulnerability.  A race condition can occur when a pair of programming calls operating simultaneously do not work in a sequential or coordinated manner.  A race condition is a timing event within software that can become a security vulnerability if the calls are not performed in the correct order.  

There are different types of race conditions and they are dependent upon the action that the application is undertaking when the race condition occurs.  Some examples of race conditions include but are not limited to:

- Time of check, time of use: the time in which a given resource is checked, and the time that resource is used.
- Thread based: two threads of execution use a resource simultaneously, resource may be invalid when used.
- Switch based: variable switches values while switch statement is in progress.

Developers must be cognizant of programming sequence and use sanity checks to validate data prior to acting upon it.

A code review or a static code analysis is the method used to identify race conditions.'
  desc 'check', 'Review the application documentation and architecture.

If the application is a COTS application and the vendor will not provide code review test results that demonstrate the application has been tested and is not susceptible to race conditions, the requirement is NA.

Interview the application admin and identify the most recent code testing and analysis that has been conducted.

Review the test results; verify configuration of analysis tools are set to check for the existence of  race conditions.  

If race conditions are identified in the test results, verify the latest test results are being used, if not, ensure remediation has been completed.

If the test results show race conditions exist and no remediation evidence is presented, or if test results are not available, this is a finding.'
  desc 'fix', 'Be aware of potential timing issues related to application programming calls when designing and building the application.

Validate that variable values do not change while a switch event is occurring.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24237r493609_chk'
  tag severity: 'medium'
  tag gid: 'V-222567'
  tag rid: 'SV-222567r879887_rule'
  tag stig_id: 'APSC-DV-001995'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24226r493610_fix'
  tag 'documentable'
  tag legacy: ['SV-84807', 'V-70185']
  tag cci: ['CCI-000366', 'CCI-003178']
  tag nist: ['CM-6 b', 'SA-11 e']
end

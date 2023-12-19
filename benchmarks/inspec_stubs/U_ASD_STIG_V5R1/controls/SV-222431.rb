control 'SV-222431' do
  title 'The application must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse, and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Log on to the application as an administrative user.

Identify functionality within the application that requires utilizing the admin role.

Monitor application logs while performing privileged functions within the application.

Perform administrative types of tasks such as adding or modifying user accounts, modifying application configuration, or managing encryption keys.

Review logs for entries that indicate the administrative actions performed were logged.

Ensure the specific action taken, date and time or event is recorded.

If the execution of privileged functionality is not logged, this is a finding.'
  desc 'fix', 'Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24101r493201_chk'
  tag severity: 'medium'
  tag gid: 'V-222431'
  tag rid: 'SV-222431r508029_rule'
  tag stig_id: 'APSC-DV-000520'
  tag gtitle: 'SRG-APP-000343'
  tag fix_id: 'F-24090r493202_fix'
  tag 'documentable'
  tag legacy: ['V-69341', 'SV-83963']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end

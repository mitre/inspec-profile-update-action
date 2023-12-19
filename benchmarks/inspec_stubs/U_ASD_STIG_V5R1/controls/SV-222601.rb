control 'SV-222601' do
  title 'The application must not store sensitive information in hidden fields.'
  desc "Hidden fields allow developers to process application data without having to display it on the screen.  Using hidden fields to pass data in forms is a common practice among web applications and by itself is not a security risk.  

However, hidden fields are not secure and can be easily manipulated by users.  Information requiring confidentiality or integrity protections must not be placed in a hidden field.   If data that is sensitive must be stored in a hidden field, it must be encrypted.

Furthermore, hidden fields used to control access decisions can lead to a complete compromise of access control mechanisms allowing immediate compromise of the user's application session."
  desc 'check', 'Interview application administrator and review application documentation to identify and familiarize with the application features and functions.

Request most recent code review and vulnerability scan results.  Review test configuration to ensure testing for hidden fields was conducted.  Review test results for incidents of hidden data fields.  

Examine identified hidden fields and determine what type of data is stored in the hidden fields.

If the data stored in the hidden fields are determined to be authentication or session related data, or if the code review or vulnerability scan results are not available and configured to test for hidden fields, this is a finding.'
  desc 'fix', 'Design and configure the application to not store sensitive information in hidden fields.  

Encrypt sensitive information stored in hidden fields using DoD-approved encryption and use server side session management techniques for user session management.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24271r493711_chk'
  tag severity: 'high'
  tag gid: 'V-222601'
  tag rid: 'SV-222601r508029_rule'
  tag stig_id: 'APSC-DV-002485'
  tag gtitle: 'SRG-APP-000441'
  tag fix_id: 'F-24260r493712_fix'
  tag 'documentable'
  tag legacy: ['V-70255', 'SV-84877']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end

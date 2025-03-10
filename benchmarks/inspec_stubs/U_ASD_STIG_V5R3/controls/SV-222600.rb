control 'SV-222600' do
  title 'The application must not disclose unnecessary information to users.'
  desc 'Applications should not disclose information not required for the transaction. (e.g., a web application should not divulge the fact there is a SQL server database and/or its version).

These events usually occur when the web application has not been configured to send specific error messages for error events. Instead, when a processing anomaly occurs, the application displays technical information about the type of application server, database in use, or other technical details.

This provides attackers additional information which they can use to find other attack avenues, or tailor specific attacks, on the application.'
  desc 'check', 'Review the application system documentation and interview the application administrators.

Ask them to demonstrate how the web server and application configuration does not disclose any information about the application which could be used by an attacker to gain access to the application.

Ask the application representative to logon as a non-privileged user and review all screens of the application to identify any potential data that should not be disclosed to the user.

Review web server configuration and determine if custom error pages are configured to display on error events.

Review error pages sent to application users to verify the pages are generic in nature and provide no technical details related to application architecture.

If the application displays any application technical data such as database version, application server information, or any other technical details that should not be disclosed to a regular user, this is a finding.'
  desc 'fix', 'Configure the application to not display technical details about the application architecture on error events.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24270r493708_chk'
  tag severity: 'medium'
  tag gid: 'V-222600'
  tag rid: 'SV-222600r879812_rule'
  tag stig_id: 'APSC-DV-002480'
  tag gtitle: 'SRG-APP-000441'
  tag fix_id: 'F-24259r493709_fix'
  tag 'documentable'
  tag legacy: ['SV-84875', 'V-70253']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end

control 'SV-54186' do
  title 'The web server must capture, record, and log all content related to a user session.'
  desc 'A user session to a web server is in the context of a user accessing a hosted application that extends to any plug-ins/modules and services that may execute on behalf of the user.

The web server must be capable of enabling a setting for troubleshooting, debugging, or forensic gathering purposes which will log all user session information related to the hosted application session. Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server captures and logs all content related to a user session.

Request a user access the hosted applications and verify the complete session is logged.

If any of the session is excluded from the log, this is a finding.'
  desc 'fix', 'Configure the web server to capture and log all content related to a user session.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48038r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41609'
  tag rid: 'SV-54186r3_rule'
  tag stig_id: 'SRG-APP-000093-WSR-000053'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag fix_id: 'F-47068r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end

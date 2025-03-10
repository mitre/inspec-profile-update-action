control 'SV-206410' do
  title 'The web server must limit the character set used for data entry.'
  desc "Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application. 

An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

The web server, by defining the character set available for data entry, can trap efforts to bypass security checks or to compromise an application."
  desc 'check', 'Review the web server documentation and deployed configuration to determine what the data set is for data entry.

If the web server does not limit the data set used for data entry, this is a finding.'
  desc 'fix', 'Configure the web server to only accept the character sets expected by the hosted applications.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6671r377822_chk'
  tag severity: 'medium'
  tag gid: 'V-206410'
  tag rid: 'SV-206410r397834_rule'
  tag stig_id: 'SRG-APP-000251-WSR-000157'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-6671r377823_fix'
  tag 'documentable'
  tag legacy: ['SV-54429', 'V-41852']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end

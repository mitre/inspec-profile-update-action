control 'SV-222983' do
  title 'Tomcat user account must be set to nologin.'
  desc 'When installing Tomcat, a user account is created on the OS. This account is used in order for Tomcat to be able to operate on the OS but does not require the ability to actually log in to the system. Therefore when the account is created, the account must not be provided access to a login shell or other program on the system. This is done by specifying the "nologin" parameter in the command/shell field of the passwd file.'
  desc 'check', 'From the command line of the Tomcat server type the following command:

sudo cat /etc/passwd|grep -i tomcat

If the command/shell field of the passwd file is not set to "/usr/sbin/nologin", this is a finding.'
  desc 'fix', 'From the Tomcat command line type the following command:

sudo usermod -s /usr/sbin/nologin tomcat'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24655r426393_chk'
  tag severity: 'medium'
  tag gid: 'V-222983'
  tag rid: 'SV-222983r615938_rule'
  tag stig_id: 'TCAT-AS-001050'
  tag gtitle: 'SRG-APP-000340-AS-000185'
  tag fix_id: 'F-24644r426394_fix'
  tag 'documentable'
  tag legacy: ['SV-111489', 'V-102549']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

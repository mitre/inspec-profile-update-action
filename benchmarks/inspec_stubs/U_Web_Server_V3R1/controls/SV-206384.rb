control 'SV-206384' do
  title 'The web server must protect system resources and privileged operations from hosted applications.'
  desc 'A web server may host one too many applications.  Each application will need certain system resources and privileged operations to operate correctly.  The web server must be configured to contain and control the applications and protect the system resources and privileged operations from those not needed by the application for operation.  

Limiting the application will confine the potential harm a compromised application could cause to a system.'
  desc 'check', 'Review the web server documentation and configuration to determine the access to server resources given to hosted applications.

If hosted applications have access to more system resources than needed for operation, this is a finding.'
  desc 'fix', 'Configure the privileges given to hosted applications to the minimum required for application operation.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6645r377744_chk'
  tag severity: 'medium'
  tag gid: 'V-206384'
  tag rid: 'SV-206384r395853_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000086'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6645r377745_fix'
  tag 'documentable'
  tag legacy: ['SV-54280', 'V-41703']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

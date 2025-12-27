control 'SV-235998' do
  title 'Oracle WebLogic must be managed through a centralized enterprise tool.'
  desc 'The application server can host multiple applications which require different functions to operate successfully but many of the functions are capabilities that are needed for all the hosted applications and should be managed through a common interface. Examples of enterprise wide functions are automated rollback of changes, failover and patching.

These functions are often outside the domain of the application server and so the application server must be integrated with a tool, such as Oracle Enterprise Manager, which is specific built to handle these requirements.'
  desc 'check', 'Review the Oracle WebLogic configuration to determine if a tool, such as Oracle Enterprise Manager, is in place to centrally manage enterprise functionality needed for Oracle WebLogic. If a tool is not in place to centrally manage enterprise functionality, this is a finding.'
  desc 'fix', 'Install a tool such as Oracle Enterprise Manager, to handle enterprise functionality such as automated failover, rollback and patching of Oracle WebLogic.'
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39217r628770_chk'
  tag severity: 'medium'
  tag gid: 'V-235998'
  tag rid: 'SV-235998r628772_rule'
  tag stig_id: 'WBLC-10-000271'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39180r628771_fix'
  tag 'documentable'
  tag legacy: ['SV-70639', 'V-56385']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

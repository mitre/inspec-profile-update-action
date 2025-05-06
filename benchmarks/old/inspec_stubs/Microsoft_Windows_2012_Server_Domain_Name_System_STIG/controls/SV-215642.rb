control 'SV-215642' do
  title 'The Windows 2012 DNS Server must, when a component failure is detected, activate a notification to the system administrator.'
  desc 'Predictable failure prevention requires organizational planning to address system failure issues. If components key to maintaining systems security fail to function, the system could continue operating in an insecure state. The organization must be prepared, and the application must support requirements that specify if the application must alarm for such conditions and/or automatically shut down the application or the system.

This can include conducting a graceful application shutdown to avoid losing information. Automatic or manual transfer of components from standby to active mode can occur, for example, upon detection of component failures.

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly anyway in this state.'
  desc 'check', 'Notification to system administrator is not configurable in Windows DNS Server. In order for system administrators to be notified when a component fails, the system administrator would need to implement a third-party monitoring system. At a minimum, the system administrator should have a documented procedure in place to review the diagnostic logs on a routine basis every day.

If a third-party monitoring system is not in place to detect and notify the system administrator upon component failures and the system administrator does not have a documented procedure in place to review the diagnostic logs on a routine basis every day, this is a finding.'
  desc 'fix', 'Implement a third-party monitoring system to detect and notify the system administrator upon component failure or, at a minimum, document and implement a procedure to review the diagnostic logs on a routine basis every day.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16836r314401_chk'
  tag severity: 'medium'
  tag gid: 'V-215642'
  tag rid: 'SV-215642r561297_rule'
  tag stig_id: 'WDNS-SI-000005'
  tag gtitle: 'SRG-APP-000268-DNS-000039'
  tag fix_id: 'F-16834r314402_fix'
  tag 'documentable'
  tag legacy: ['SV-73141', 'V-58711']
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end

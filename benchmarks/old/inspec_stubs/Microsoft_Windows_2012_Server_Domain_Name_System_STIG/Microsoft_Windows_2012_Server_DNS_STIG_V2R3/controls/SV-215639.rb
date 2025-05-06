control 'SV-215639' do
  title 'The Windows 2012 DNS Server must follow procedures to re-role a secondary name server as the master name server should the master name server permanently lose functionality.'
  desc 'Failing to an unsecure condition negatively impacts application security and can lead to system compromise. Failure conditions include, for example, loss of communications among critical system components or between system components and operational facilities. Fail-safe procedures include, for example, alerting operator personnel and providing specific instructions on subsequent steps to take (e.g., do nothing, reestablish system settings, shutdown processes, restart the system, or contact designated organizational personnel).

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly anyway in this state.'
  desc 'check', 'Active Directory integrated DNS servers will handle the promotion of a secondary DNS server whenever a primary DNS server loses functionality.

If all of the DNS servers are AD-integrated, this is not a finding.

Consult with the System Administrator to determine if there are documented procedures for re-roling a non-AD-integrated secondary name server to a master name server role in the event a master name server loses functionality.

If there is not any documented procedures for re-roling a non-AD-integrated secondary name server to primary in the event a master name server loses functionality, this is a finding.'
  desc 'fix', 'Active Directory-integrated DNS servers will handle the promotion of a secondary DNS server whenever a primary DNS server loses functionality.

Develop, test, and implement documented procedures for re-roling a non-AD-integrated secondary name server to a master name server role in the event a master name server loses functionality.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16833r314392_chk'
  tag severity: 'medium'
  tag gid: 'V-215639'
  tag rid: 'SV-215639r561297_rule'
  tag stig_id: 'WDNS-SI-000002'
  tag gtitle: 'SRG-APP-000451-DNS-000069'
  tag fix_id: 'F-16831r314393_fix'
  tag 'documentable'
  tag legacy: ['SV-73139', 'V-58709']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end

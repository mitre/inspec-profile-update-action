control 'WDNS-22-000074_rule' do
  title 'The Windows 2022 DNS Server must follow procedures to re-role a secondary name server as the primary name server if the primary name server permanently loses functionality.'
  desc 'Failing to an unsecure condition negatively impacts application security and can lead to system compromise. Failure conditions include, for example, loss of communications among critical system components or between system components and operational facilities. Fail-safe procedures include, for example, alerting operator personnel and providing specific instructions on subsequent steps to take (e.g., do nothing, reestablish system settings, shutdown processes, restart the system, or contact designated organizational personnel).

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly in this state.'
  desc 'check', 'Active Directory (AD)-integrated DNS servers will handle the promotion of a secondary DNS server when a primary DNS server loses functionality.

If all of the DNS servers are AD integrated, this is not a finding.

Consult with the system administrator to determine if there are documented procedures to re-role a non-AD-integrated secondary name server to a master name server role if a master name server loses functionality.

If there are no documented procedures to re-role a non-AD-integrated secondary name server to primary if a master name server loses functionality, this is a finding.'
  desc 'fix', 'AD-integrated DNS servers will handle the promotion of a secondary DNS server when a primary DNS server loses functionality.

Develop, test, and implement documented procedures to re-role a non-AD-integrated secondary name server to a master name server role if a master name server loses functionality.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000074_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000074'
  tag rid: 'WDNS-22-000074_rule'
  tag stig_id: 'WDNS-22-000074'
  tag gtitle: 'SRG-APP-000451-DNS-000069'
  tag fix_id: 'F-WDNS-22-000074_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002775']
  tag nist: ['CM-6 b', 'SI-17']
end

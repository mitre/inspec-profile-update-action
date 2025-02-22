control 'SV-205221' do
  title 'The DNS server implementation must follow procedures to re-role a secondary name server as the master name server should the master name server permanently lose functionality.'
  desc 'Failing to an unsecure condition negatively impacts application security and can lead to system compromise. Failure conditions include, for example, loss of communications among critical system components or between system components and operational facilities. Fail-safe procedures include, for example, alerting operator personnel and providing specific instructions on subsequent steps to take (e.g., do nothing, reestablish system settings, shut down processes, restart the system, or contact designated organizational personnel).

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly anyway in this state.'
  desc 'check', 'Review the DNS server implementation operating documentation to determine if procedures exist to promote a secondary name server to the master in the event the master DNS name server permanently loses functionality.

If procedures do not exist to promote a secondary name server to the master in the event the master DNS name server permanently loses functionality, this is a finding.'
  desc 'fix', 'Develop internal procedures to ensure a secondary name server to the master in the event the master DNS name server permanently loses functionality.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5488r392576_chk'
  tag severity: 'medium'
  tag gid: 'V-205221'
  tag rid: 'SV-205221r879822_rule'
  tag stig_id: 'SRG-APP-000451-DNS-000069'
  tag gtitle: 'SRG-APP-000451'
  tag fix_id: 'F-5488r392577_fix'
  tag 'documentable'
  tag legacy: ['SV-69149', 'V-54903']
  tag cci: ['CCI-002775', 'CCI-000366']
  tag nist: ['SI-17', 'CM-6 b']
end

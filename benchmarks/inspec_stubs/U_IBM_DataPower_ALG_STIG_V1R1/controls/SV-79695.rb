control 'SV-79695' do
  title 'The DataPower Gateway that provides intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks which exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol thus are in scope for this requirement. NIS SP 800-52 provides guidance.

SP 800-52 sets TLS version 1.1 as a minimum version, thus all versions of SSL are not allowed (including for client negotiation) either on DoD-only or on public facing servers.'
  desc 'check', 'In the search field, enter "SSL Server Profile" >> Select "SSL Server Profile" from the results >> Click the name of the SSL Server Profile object to be inspected >> Confirm that the TLS 1.1 and TLS 1.2 protocol options are checked.

If they are not checked, this is a finding.'
  desc 'fix', 'The implementer will configure an "SSL Server Profile" to be used for SSL negotiation of a given service. 

In the search field, enter "SSL Server Profile" >> Select "SSL Server Profile" from the results >> Click "Add" >> Configure the SSL Server Profile, providing a logical object name and appropriate selection of settings (depending on what type of SSL connection is to be implemented - forward, reverse, mutual) >> Protocols to be enabled include TLS 1.1 and 1.2 (both are enabled by default).'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65833r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65205'
  tag rid: 'SV-79695r1_rule'
  tag stig_id: 'WSDP-AG-000018'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-71145r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

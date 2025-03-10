control 'SV-243195' do
  title 'The network device must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the network device configuration to verify only secure protocols using FIPS 140-2 validated cryptographic modules are used for any administrative access. Some of the secure protocols used for administrative and management access are listed below. This list is not all inclusive and represents a sample selection of secure protocols. 

- SSHv2
- SCP
- HTTPS using TLS

If management connections are established using protocols without FIPS 140-2 validated cryptographic modules, this is a finding.'
  desc 'fix', 'Configure the network device to use secure protocols with FIPS 140-2 validated cryptographic modules.'
  impact 0.7
  ref 'DPMS Target Network WLAN Controller Mgmt'
  tag check_id: 'C-46470r720038_chk'
  tag severity: 'high'
  tag gid: 'V-243195'
  tag rid: 'SV-243195r720040_rule'
  tag stig_id: 'WLAN-ND-000800'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-46427r720039_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end

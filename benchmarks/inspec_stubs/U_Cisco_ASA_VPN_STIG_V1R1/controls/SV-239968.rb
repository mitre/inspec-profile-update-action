control 'SV-239968' do
  title 'The Cisco ASA remote access VPN server must be configured to enforce certificate-based authentication before granting access to the network.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Use of password for user remote access for non-privileged account is not authorized.

Factors include:
(i) Something you know (e.g., password/PIN);
(ii) Something you have (e.g., cryptographic identification device, token); or
(iii) Something you are (e.g., biometric).

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to a network element by a user (or a process acting on behalf of a user) communicating through a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Review the ASA configuration to verify that it enforces certificate-based authentication before granting access to the network as shown in the example below.

tunnel-group ANY_CONNECT type remote-access
tunnel-group ANY_CONNECT webvpn-attributes
 authentication certificate

If the ASA configuration does not enforce certificate-based authentication before granting access to the network, this is a finding.'
  desc 'fix', 'Configure the ASA to enforce certificate-based authentication before granting access to the network as shown in the example below.

ASA1(config)# tunnel-group ANY_CONNECT webvpn-attributes
ASA1(config-tunnel-webvpn)# authentication certificate 
ASA1(config-tunnel-webvpn)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43201r666308_chk'
  tag severity: 'high'
  tag gid: 'V-239968'
  tag rid: 'SV-239968r666310_rule'
  tag stig_id: 'CASA-VN-000440'
  tag gtitle: 'SRG-NET-000140-VPN-000500'
  tag fix_id: 'F-43160r666309_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end

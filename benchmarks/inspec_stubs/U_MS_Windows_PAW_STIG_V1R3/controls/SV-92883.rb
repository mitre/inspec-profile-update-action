control 'SV-92883' do
  title 'The Windows PAW must use a trusted channel for all connections between a PAW and IT resources managed from the PAW.'
  desc 'Note: The Common Criteria Security Functional Requirement (SFR) FTP_ITC.1.1(1) defines "trusted channel" as "a channel that uses IPsec, SSH, TLS, or TLS/HTTPS to provide a trusted communications channel between itself and authorized IT entity that is logically distinct from other communication channels and provides assured identification of its end points and protection of the channel data from modification or disclosure." The trusted channel uses IPsec, TLS, DTLS, or HTTPS as the protocol that preserves the confidentiality and integrity of PAW communications.

The confidentiality and integrity of the communications between the PAW and high-value IT resources being managed from the PAW must be protected due to the highly sensitive nature of the administrative functions being performed. A trusted channel provides the requisite assured identification of its end points and protection of the channel data from modification or disclosure.'
  desc 'check', 'On the PAW workstation, verify IPsec, SSH, TLS, or TLS/HTTPS is configured for all connections between the PAW and managed IT resources on the intranet.

Verify the following registry setting:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

Value Name: Enabled

Value Type: REG_DWORD
Value: 1

Warning: Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms. Both the browser and web server must be configured to use TLS; otherwise, the browser will not be able to connect to a secure site.

If on the PAW workstation the registry value for HKEY_LOCAL_MACHINE does not exist or is not configured as specified, this is a finding.'
  desc 'fix', 'Configure the PAWs to use IPsec, SSH, TLS, or TLS/HTTPS for all connections between the PAW and managed IT resources on the intranet.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77743r5_chk'
  tag severity: 'high'
  tag gid: 'V-78177'
  tag rid: 'SV-92883r1_rule'
  tag stig_id: 'WPAW-00-001700'
  tag gtitle: 'PAW-00-001700'
  tag fix_id: 'F-84899r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001135', 'CCI-001136', 'CCI-002426']
  tag nist: ['SC-11 a', 'SC-11', 'SC-11 (1) (a)']
end

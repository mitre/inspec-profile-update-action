control 'SV-237048' do
  title 'The A10 Networks ADC being used for TLS encryption and decryption using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certificate Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the device with TLS enabled will require the installation of DoD and/or DoD-Approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic.

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'If the A10 Networks ADC is not used for TLS/SSL decryption for application traffic, this is not applicable.

If the A10 Networks ADC is used for TLS/SSL decryption for application traffic, verify the A10 Networks ADC only accepts end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions.

If the A10 Networks ADC accepts non-DoD-approved PKI end entity certificates, this is a finding.'
  desc 'fix', 'If the A10 Networks ADC is used for TLS/SSL decryption for application traffic, import the root and intermediate CA certificates. The certificates can be imported onto the device using FTP or SCP.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40267r639589_chk'
  tag severity: 'medium'
  tag gid: 'V-237048'
  tag rid: 'SV-237048r639591_rule'
  tag stig_id: 'AADC-AG-000098'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-40230r639590_fix'
  tag 'documentable'
  tag legacy: ['SV-82483', 'V-67993']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

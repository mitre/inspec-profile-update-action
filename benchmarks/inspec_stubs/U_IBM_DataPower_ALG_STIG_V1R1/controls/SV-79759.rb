control 'SV-79759' do
  title 'The DataPower Gateway providing user authentication intermediary services using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-Approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. 

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'Type “Validation Credential” in the nav search. Verify that ValCred has only DoD certs. If ValCred does not contain DoD certs, this is a finding.

Check config of active SSL Proxy Profiles to ensure use of ValCred. If SSL Proxy does not contain a ValCred, this is a finding.'
  desc 'fix', 'Type “Validation Credential” in search bar. Create ValCred with only DoD certs. When creating SSL Proxy Profiles, require mutual authentication; then use ValCred with only DoD certs.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65269'
  tag rid: 'SV-79759r1_rule'
  tag stig_id: 'WSDP-AG-000098'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-71209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

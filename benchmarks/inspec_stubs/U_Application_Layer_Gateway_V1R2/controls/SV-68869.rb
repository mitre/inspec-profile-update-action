control 'SV-68869' do
  title 'The ALG providing user authentication intermediary services using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-Approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. 

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'If the ALG does not provide PKI-based user authentication intermediary services, this is not applicable.

Verify the ALG only accepts end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions.

If the ALG accepts non-DoD approved PKI end entity certificates, this is a finding.'
  desc 'fix', 'If PKI-based user authentication intermediary services are provided, configure the ALG to only accept end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55243r3_chk'
  tag severity: 'medium'
  tag gid: 'V-54623'
  tag rid: 'SV-68869r1_rule'
  tag stig_id: 'SRG-NET-000355-ALG-000117'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-59479r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

control 'SV-91129' do
  title 'Kona Site Defender providing user authentication intermediary services using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-approved external PKIs are PIV issuers. Category II DoD-approved external PKIs are Non-Federal Agency PKIs cross-certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-approved external PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. 

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'If Kona Site Defender is providing user authentication intermediary services, confirm that it accepts only end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions:

Contact the Akamai Professional Services team to confirm accepted certificate authorities at 1-877-4-AKATEC (1-877-425-2832).

If the Akamai Professional Services team confirms that the list of accepted certificate authorities is not issued by DoD-approved PKI certification authorities, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to accept only end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions:

Contact the Akamai Professional Services team to implement the changes at 1-877-4-AKATEC (1-877-425-2832).'
  impact 0.7
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76093r1_chk'
  tag severity: 'high'
  tag gid: 'V-76433'
  tag rid: 'SV-91129r1_rule'
  tag stig_id: 'AKSD-WF-000025'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-83111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

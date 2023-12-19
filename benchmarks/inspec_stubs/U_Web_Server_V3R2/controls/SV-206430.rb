control 'SV-206430' do
  title 'The web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', 'Review the web server deployed configuration to determine if the web server will accept client certificates issued by unapproved PKIs. The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability.

If the web server will accept non-DoD approved PKI client certificates, this is a finding.'
  desc 'fix', 'Configure the web server to only accept DoD and DoD-approved PKI client certificates.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6691r377882_chk'
  tag severity: 'medium'
  tag gid: 'V-206430'
  tag rid: 'SV-206430r879798_rule'
  tag stig_id: 'SRG-APP-000427-WSR-000186'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-6691r377883_fix'
  tag 'documentable'
  tag legacy: ['SV-70281', 'V-56027']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

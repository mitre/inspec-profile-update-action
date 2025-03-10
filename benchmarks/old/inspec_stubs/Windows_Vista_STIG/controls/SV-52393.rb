control 'SV-52393' do
  title 'The US DoD CCEB Interoperability Root CA cross-certificate must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificate must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'fix', 'Install the US DoD CCEB Interoperability Root CA cross-certificate on unclassified systems.

Issued To - Issued By - Thumbprint
DoD Root CA 2 - US DoD CCEB Interoperability Root CA 1 - DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3

Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.

The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-40237'
  tag rid: 'SV-52393r3_rule'
  tag stig_id: 'WINPK-000004'
  tag gtitle: 'WINPK-000004'
  tag fix_id: 'F-76963r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end

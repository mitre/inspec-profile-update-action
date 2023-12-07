control 'SV-42604' do
  title 'The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'fix', 'Install the DoD Interoperability Root CA cross-certificates on unclassified systems.

Issued To - Issued By - Thumbprint
DoD Root CA 2 - DoD Interoperability Root CA 1 - 99C494ECE4FC093EEE13C4D65B1B1E01B9B5D434
DoD Root CA 3 - DoD Interoperability Root CA 2 - FFAD03329B9E527A43EEC66A56F9CBB5393E6E13
DoD Root CA 3 - DoD Interoperability Root CA 2 - FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4

Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.

The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-32274'
  tag rid: 'SV-42604r5_rule'
  tag stig_id: 'WINPK-000003'
  tag gtitle: 'WINPK-000003'
  tag fix_id: 'F-76961r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end

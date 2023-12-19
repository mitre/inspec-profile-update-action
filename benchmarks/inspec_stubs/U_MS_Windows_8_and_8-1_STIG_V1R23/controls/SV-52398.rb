control 'SV-52398' do
  title 'The US DoD CCEB Interoperability Root CA cross-certificate must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificate must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the US DoD CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an Untrusted Certificate.

Run "PowerShell" as an administrator.
Execute the following command:
Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint
If the following information is not displayed, this is finding.

Subject: CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3

Alternately use the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Untrusted Certificates >> Certificates".

For each certificate with "US DoD CCEB Interoperability Root CA …" under "Issued By":
Right click on the certificate and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint".

If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Issued To - Issued By - Thumbprint
DoD Root CA 2 - US DoD CCEB Interoperability Root CA 1 - DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3'
  desc 'fix', 'Install the US DoD CCEB Interoperability Root CA cross-certificate on unclassified systems.

Issued To - Issued By - Thumbprint
DoD Root CA 2 - US DoD CCEB Interoperability Root CA 1 - DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3

Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.

The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-71133r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40237'
  tag rid: 'SV-52398r3_rule'
  tag stig_id: 'WN08-PK-000004'
  tag gtitle: 'WINPK-000004'
  tag fix_id: 'F-76977r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end

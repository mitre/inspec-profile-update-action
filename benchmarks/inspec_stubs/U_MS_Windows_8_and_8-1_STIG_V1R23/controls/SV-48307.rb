control 'SV-48307' do
  title 'The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the DoD Interoperability cross-certificates are installed on unclassified systems as Untrusted Certificates.

Run "PowerShell" as an administrator.
Execute the following command:
Get-ChildItem -Path Cert:Localmachine\\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint
If the following information is not displayed, this is finding.

Subject: CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 22BBE981F0694D246CC1472ED2B021DC8540A22F

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: FFAD03329B9E527A43EEC66A56F9CBB5393E6E13

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4

Alternately use the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Untrusted Certificates >> Certificates".

For each certificate with "DoD Root CA…" under "Issued To" and "DoD Interoperability Root CA…" under "Issued By":
Right click on the certificate and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint".

If the certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Issued To - Issued By - Thumbprint
DoD Root CA 2 - DoD Interoperability Root CA 1 - 22BBE981F0694D246CC1472ED2B021DC8540A22F
DoD Root CA 3 - DoD Interoperability Root CA 2 - FFAD03329B9E527A43EEC66A56F9CBB5393E6E13
DoD Root CA 3 - DoD Interoperability Root CA 2 - FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4'
  desc 'fix', 'Install the DoD Interoperability Root CA cross-certificates on unclassified systems.

Issued To - Issued By - Thumbprint
DoD Root CA 2 - DoD Interoperability Root CA 1 - 22BBE981F0694D246CC1472ED2B021DC8540A22F
DoD Root CA 3 - DoD Interoperability Root CA 2 - FFAD03329B9E527A43EEC66A56F9CBB5393E6E13
DoD Root CA 3 - DoD Interoperability Root CA 2 - FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4

Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.

The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-72751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-32274'
  tag rid: 'SV-48307r5_rule'
  tag stig_id: 'WN08-PK-000003'
  tag gtitle: 'WINPK-000003'
  tag fix_id: 'F-78943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end

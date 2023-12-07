control 'SV-254442' do
  title 'Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.'
  desc 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs. The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.

'
  desc 'check', 'The certificates and thumbprints referenced below apply to unclassified systems; refer to PKE documentation for other networks.

Open "Windows PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
NotAfter: 12/30/2029

Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
NotAfter: 7/25/2032

Subject: CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
NotAfter: 6/14/2041

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".

For each of the DoD Root CA certificates noted below:

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the DoD Root CA certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

DoD Root CA 3
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
Valid to: Sunday, December 30, 2029

DoD Root CA 4
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
Valid to: Sunday, July 25, 2032

DoD Root CA 5
Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
Valid to: Friday, June 14, 2041'
  desc 'fix', 'Install the DoD Root CA certificates:

DoD Root CA 3
DoD Root CA 4
DoD Root CA 5

The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57927r894653_chk'
  tag severity: 'medium'
  tag gid: 'V-254442'
  tag rid: 'SV-254442r894653_rule'
  tag stig_id: 'WN22-PK-000010'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-57878r890549_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000403-GPOS-00182']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end

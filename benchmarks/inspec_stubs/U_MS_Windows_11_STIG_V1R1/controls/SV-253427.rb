control 'SV-253427' do
  title 'The DoD Root CA certificates must be installed in the Trusted Root Store.'
  desc 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certificate Authorities (CAs). The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.'
  desc 'check', 'Verify the DoD Root CA certificates are installed as Trusted Root Certification Authorities.

The certificates and thumbprints referenced below apply to unclassified systems; see PKE documentation for other networks.

Run "PowerShell" as an administrator.

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

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to Trusted Root Certification Authorities >> Certificates.

For each of the DoD Root CA certificates noted below:

Right-click on the certificate and select "Open".

Select the "Details" Tab.

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
  desc 'fix', 'Install the DoD Root CA certificates.
DoD Root CA 3
DoD Root CA 4
DoD Root CA 5

The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56880r829363_chk'
  tag severity: 'medium'
  tag gid: 'V-253427'
  tag rid: 'SV-253427r829365_rule'
  tag stig_id: 'WN11-PK-000005'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-56830r829364_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

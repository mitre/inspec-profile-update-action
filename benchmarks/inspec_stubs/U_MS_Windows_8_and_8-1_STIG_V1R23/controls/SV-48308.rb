control 'SV-48308' do
  title 'The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems.'
  desc 'To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly validated, the system must trust the ECA Root CAs. The ECA root certificates will ensure the trust chain is established for server certificates issued from the External CAs. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the ECA Root CA certificates are installed on unclassified systems as Trusted Root Certification Authorities.

Run "PowerShell" as an administrator.
Execute the following command:
Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint
If the following information is not displayed, this is finding.

Subject: CN=ECA Root CA 2, OU=ECA, O=U.S. Government, C=US
Thumbprint: C313F919A6ED4E0E8451AFA930FB419A20F181E4

Subject: CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US
Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582

Alternately use the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".
If there are no entries for "ECA Root CA 2", and "ECA Root CA 4", this is a finding.

For each of the ECA Root CA certificates noted above:
Right click on the certificate and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint".

If the value for the "Thumbprint" field is not as noted below, this is a finding.
ECA Root CA 2 - C313F919A6ED4E0E8451AFA930FB419A20F181E4
ECA Root CA 4 - 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582'
  desc 'fix', 'Install the ECA Root CA certificates on unclassified systems.
ECA Root CA 2
ECA Root CA 4

The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-71129r2_chk'
  tag severity: 'medium'
  tag gid: 'V-32273'
  tag rid: 'SV-48308r3_rule'
  tag stig_id: 'WN08-PK-000002'
  tag gtitle: 'WINPK-000002'
  tag fix_id: 'F-76973r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

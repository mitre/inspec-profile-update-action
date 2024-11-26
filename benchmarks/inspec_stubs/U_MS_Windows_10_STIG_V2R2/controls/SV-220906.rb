control 'SV-220906' do
  title 'The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the US DoD CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an Untrusted Certificate.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint", information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S.Government, C=US
Thumbprint: AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9
NotAfter: 8/26/2022 9:07:50 AM

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Untrusted Certificates >> Certificates".

For each certificate with "US DoD CCEB Interoperability Root CA …" under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S.Government, C=US
Thumbprint: AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9
NotAfter: 8/26/2022 9:07:50 AM'
  desc 'fix', 'Install the US DoD CCEB Interoperability Root CA cross-certificate on unclassified systems.

Issued To - Issued By - Thumbprint
DoD Root CA 3 - US DoD CCEB Interoperability Root CA 2 - AF132AC65DE86FC4FB3FE51FD637EBA0FF0B12A9

The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files.'
  impact 0.5
  ref 'DPMS Target Windows 10'
  tag check_id: 'C-22621r603136_chk'
  tag severity: 'medium'
  tag gid: 'V-220906'
  tag rid: 'SV-220906r569316_rule'
  tag stig_id: 'WN10-PK-000020'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-22610r603234_fix'
  tag 'documentable'
  tag legacy: ['SV-78079', 'V-63589']
  tag cci: ['CCI-002470', 'CCI-000185']
  tag nist: ['SC-23 (5)', 'IA-5 (2) (b) (1)']
end

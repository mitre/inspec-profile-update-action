control 'SV-225023' do
  title 'The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.

'
  desc 'check', 'Verify the US DoD CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an Untrusted Certificate.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025

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
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025'
  desc 'fix', 'Install the US DoD CCEB Interoperability Root CA cross-certificate on unclassified systems.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025

The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26714r890512_chk'
  tag severity: 'medium'
  tag gid: 'V-225023'
  tag rid: 'SV-225023r890514_rule'
  tag stig_id: 'WN16-PK-000030'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-26702r890513_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000403-GPOS-00182']
  tag 'documentable'
  tag legacy: ['V-73609', 'SV-88273']
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end

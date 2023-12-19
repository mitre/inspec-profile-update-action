control 'SV-253429' do
  title 'The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the DoD Interoperability cross-certificates are installed on unclassified systems as Untrusted Certificates.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint", information is not displayed, this is a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 49CBE933151872E17C8EAE7F0ABA97FB610F6477
NotAfter: 11/16/2024 
           
Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: AC06108CA348CC03B53795C64BF84403C1DBD341
NotAfter: 1/22/2022 

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.

For each certificate with "DoD Root CA...." under "Issued To" and "DoD Interoperability Root CA...." under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" Tab.

Scroll to the bottom and select "Thumbprint".

If the certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Issued To: DoD Root CA 3
Issued By: Interoperability Root CA 2
Thumbprint : 49CBE933151872E17C8EAE7F0ABA97FB610F6477
Valid to: Saturday, November 16, 2024

Issued To: DoD Root CA 3
Issued By: DoD Interoperability Root CA 2
Thumbprint: AC06108CA348CC03B53795C64BF84403C1DBD341
Valid to: Saturday, January 22, 2022'
  desc 'fix', 'Install the DoD Interoperability Root CA cross-certificates on unclassified systems.  
                                           
Issued To - Issued By - Thumbprint
DoD Root CA 3 - DoD Interoperability Root CA 2 - AC06108CA348CC03B53795C64BF84403C1DBD341

The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56882r829369_chk'
  tag severity: 'medium'
  tag gid: 'V-253429'
  tag rid: 'SV-253429r829371_rule'
  tag stig_id: 'WN11-PK-000015'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-56832r829370_fix'
  tag 'documentable'
  tag cci: ['CCI-002440']
  tag nist: ['SC-12']
end

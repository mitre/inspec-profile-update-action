control 'SV-52391' do
  title 'The US DoD CCEB Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed into the Untrusted Certificates Store.'
  desc 'To ensure users do not experience denial of service on NIPRNet when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CA 2, the US DoD CCEB Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed in the Untrusted Certificate Store.  This requirement only applies to NIPRNet systems.'
  desc 'check', 'Verify the DoD Root CA 2 certificate issued by US DoD CCEB Interoperability Root CA 1 is installed on NIPRNet systems as an Untrusted Certificate using the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Click "Add".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "Close".
Click "OK".
Expand "Certificates" and navigate to "Untrusted Certificates\\Certificates".
Search in the right pane for "DoD Root CA 2" under "Issued To" with "US DoD CCEB Interoperability Root CA 1" as "Issued By".

If there is no entry for this certificate, this is a finding.

Select the certificate.
Right click and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint Algorithm".
Verify the Value is "sha1".

If the value for "Thumbprint Algorithm" is not "sha1", this is a finding.

Next select "Thumbprint".

If the value for the "Thumbprint" field is not
"7d:a8:e8:42:96:ee:23:88:18:ee:42:72:87:77:45:08:b2:6d:09:4a", this is a finding.'
  desc 'fix', 'Install the US DoD CCEB Interoperability Root CA 1 to DoD Root CA 2 cross-certificate on NIPRNet systems only.  Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.  The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-49214r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40237'
  tag rid: 'SV-52391r2_rule'
  tag stig_id: 'WINPK-000004'
  tag gtitle: 'WNPK-000004'
  tag fix_id: 'F-48776r1_fix'
  tag 'documentable'
  tag ia_controls: 'IATS-1, IATS-2'
end

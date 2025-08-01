control 'SV-226265' do
  title 'Domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority (ECA).'
  desc 'A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure. Without proper practices, the certificates issued by a CA have limited value in authentication functions.  The use of multiple CAs from separate PKI implementations results in interoperability issues.  If servers and clients do not have a common set of root CA certificates, they are not able to authenticate each other.'
  desc 'check', %q(Verify the source of the domain controller's server certificate.

Run "mmc".
Select "Add/Remove Snap-in" from the File menu.
Select "Certificates" in the left pane and click the "Add >" button.
Select "Computer Account", click "Next".
Select the appropriate option for "Select the computer you want this snap-in to manage.", click "Finish".
Click "OK".
Select and expand the Certificates (Local Computer) entry in the left pane.
Select and expand the Personal entry in the left pane.
Select the Certificates entry in the left pane.
In the right pane, examine the Issued By field for the certificate to determine the issuing CA.

If the Issued By field of the PKI certificate being used by the domain controller does not indicate the issuing Certificate Authority (CA) is part of the DoD PKI or an approved ECA, this is a finding.


There are multiple sources from which lists of valid DoD CAs and approved ECAs can be obtained: 

The Global Directory Service (GDS) website provides an online source. The address for this site is https://crl.gds.disa.mil.

DoD Public Key Enablement (PKE) Engineering Support maintains the InstallRoot utility to manage DoD supported root certificates on Windows computers which includes a list of authorized CAs.  The utility package can be downloaded from the PKI and PKE Tools page on IASE.  
http://iase.disa.mil/pki-pke/function_pages/tools.html)
  desc 'fix', "Obtain PKI certificates issued by the DoD PKI or an approved External Certificate Authority (ECA).

Severity Override Guidance: If the certificates in use are issued by a CA authorized by the Component's CIO, this is a CAT II finding.

IA Controls: IAKM-1, IAKM-2, IATS-1, IATS-2"
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27967r476639_chk'
  tag severity: 'high'
  tag gid: 'V-226265'
  tag rid: 'SV-226265r794525_rule'
  tag stig_id: 'WN12-PK-000006-DC'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-27955r794524_fix'
  tag 'documentable'
  tag legacy: ['V-14820', 'SV-51190']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

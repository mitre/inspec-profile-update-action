control 'SV-78389' do
  title 'The VMM must electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.'
  desc 'check', 'From the vSphere Web Client, select the ESXi Host and go to Manage >> Authentication Services.

View the "Smart Card Authentication" status.

If "Enable Smart Card Authentication" is checked, the system requires smart cards to authenticate to an Active Directory Domain.

For systems that have no local user accounts, other than root, dcui, and/or vpxuser, this is Not Applicable.

For environments that do not use vCenter server to manage ESXi, this is Not Applicable.

For systems that do not use smart cards with Active Directory and do have local user accounts, other than root, dcui, and/or vpxuser, this is a finding.'
  desc 'fix', %q(The following are pre-requisites to configuration smart card authentication for the ESXi DCUI:
-Active Directory domain that supports smart card authentication, smart card readers, and smart cards.
-ESXi joined to an Active Directory domain.
-Trusted certificates for root and intermediary certificate authorities.

From the vSphere Web Client, select the ESXi Host and go to Manage >> Authentication Services.

Edit the "Smart Card Authentication" configuration to add trusted certificate authority certificates.

Select "Enable Smart Card Authentication".

Click OK.

For more information see the vSphere 6.0 documentation on VMware's website.)
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64649r2_chk'
  tag severity: 'low'
  tag gid: 'V-63899'
  tag rid: 'SV-78389r2_rule'
  tag stig_id: 'ESXI-06-200040'
  tag gtitle: 'SRG-OS-000377-VMM-001530'
  tag fix_id: 'F-69827r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end

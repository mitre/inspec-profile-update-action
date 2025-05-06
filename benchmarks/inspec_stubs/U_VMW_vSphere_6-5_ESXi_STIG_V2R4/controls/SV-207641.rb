control 'SV-207641' do
  title 'The ESXi host must use multifactor authentication for local access to privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Authentication Services and view the Smart Card Authentication status. If "Enable Smart Card Authentication" is checked, the system requires smart cards to authentication to an Active Directory Domain.

For systems that have no local user accounts, other than root and/or vpxuser, this is not applicable.

For environments that do not use vCenter server to manage ESXi, this is not applicable.

For systems that do not use smart cards with Active Directory and do have local user accounts, other than root and/or vpxuser, this is a finding.'
  desc 'fix', 'The following are pre-requisites to configuration smart card authentication for the ESXi DCUI: 
-Active Directory domain that supports smart card authentication, smart card readers, and smart cards. 
-ESXi joined to an Active Directory domain. 
-Trusted certificates for root and intermediary certificate authorities. 

From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Authentication Services and click Edit and check "Enable Smart Card Authentication" checkbox, at the Certificates tab, click the green plus sign to import trusted certificate authority certificates and click OK.'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7896r364322_chk'
  tag severity: 'low'
  tag gid: 'V-207641'
  tag rid: 'SV-207641r378856_rule'
  tag stig_id: 'ESXI-65-000040'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag fix_id: 'F-7896r364323_fix'
  tag 'documentable'
  tag legacy: ['SV-104113', 'V-94027']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end

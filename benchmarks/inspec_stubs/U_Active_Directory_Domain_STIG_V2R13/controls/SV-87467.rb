control 'SV-87467' do
  title 'All accounts, privileged and unprivileged, that require smart cards must have the underlying NT hash rotated at least every 60 days.'
  desc 'When a smart card is required for a domain account, a long password, unknown to the user, is generated. This password and associated NT hash are not changed as are accounts with passwords controlled by the maximum password age. Disabling and re-enabling the "Smart card is required for interactive logon" (SCRIL) replaces the NT hash of the account with a newly randomized hash. Otherwise, the existing NT hash could be reused for Pass-the-Hash in the future.

Windows Server 2016 includes a built-in feature for SCRIL hash rolling that will automatically reset NT hashes in accordance with the existing maximum password age policy.  This requires the domain functional level to be Windows Server 2016.

In Active Directory with a domain functional level below Windows Server 2016, scripts can be used to reset the NT hashes of all domain accounts. Associated documentation should be reviewed for potential issues.'
  desc 'check', 'Windows Server 2016 with a domain functional level of Windows Server 2016:

Open "Active Directory Administrative Center".

Right-click on the domain name and select "Properties".

If the "Domain functional level:" is not "Windows Server 2016", another method must be used to reset the NT hashes.  See below for other options.

If the "Domain functional level:" is "Windows Server 2016" and "Enable rolling of expiring NTLM secrets during sign on, for users who are required to use Microsoft Passport or smart card for interactive sign on" is not checked, this is a finding.

Active Directory domains with a domain functional level below Windows Server 2016:

Verify the organization rotates the NT hash for smart card-enforced accounts every 60 days.  

This can be accomplished with the use of scripts.  

DoD PKI-PKE has provided a script under PKI and PKE Tools at http://iase.disa.mil/pki-pke/Pages/tools.aspx.  See the User Guide for additional information.

NSA has also provided a PowerShell script with Pass-the-Hash guidance at https://github.com/iadgov/Pass-the-Hash-Guidance.  Running the "Invoke-SmartcardHashRefresh" cmdlet in the "PtHTools" module will trigger a change of the underlying NT hash.  See the site for additional information.

Manually rolling the NT hash requires disabling and re-enabling the "Smart Card required for interactive logon" option for each smart card-enforced account, which is not practical for large groups of users.

If NT hashes for smart card-enforced accounts are not rotated every 60 days, this is a finding.'
  desc 'fix', 'Windows Server 2016 with domain functional levels of Windows Server 2016:

Open "Active Directory Administrative Center".

Right-click on the domain name and select "Properties".

Select "Enable rolling of expiring NTLM secrets during sign on, for users who are required to use Microsoft Passport or smart card for interactive sign on".

Active Directory domains not at a Windows Server 2016 domain functional level:

Rotate the NT hash for smart card-enforced accounts every 60 days.

This can be accomplished with the use of scripts.  

DoD PKI-PKE has provided a script under PKI and PKE Tools at http://iase.disa.mil/pki-pke/Pages/tools.aspx.  See the User Guide for additional information.

NSA has also provided a PowerShell script with Pass-the-Hash guidance at https://github.com/iadgov/Pass-the-Hash-Guidance.  Running the "Invoke-SmartcardHashRefresh" cmdlet in the "PtHTools" module will trigger a change of the underlying NT hash.  See the site for additional information.

Manually rolling the NT hash requires disabling and re-enabling the "Smart Card required for interactive logon" option for each smart card-enforced account, which is not practical for large groups of users.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-72939r3_chk'
  tag severity: 'medium'
  tag gid: 'V-72821'
  tag rid: 'SV-87467r1_rule'
  tag stig_id: 'AD.0016'
  tag gtitle: 'AD.0016'
  tag fix_id: 'F-79245r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

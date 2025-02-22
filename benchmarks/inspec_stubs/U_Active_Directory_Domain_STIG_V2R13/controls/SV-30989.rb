control 'SV-30989' do
  title 'Each cross-directory authentication configuration must be documented.'
  desc 'Active Directory (AD) external, forest, and realm trust configurations are designed to extend resource access to a wider range of users (those in other directories).  If specific baseline documentation of authorized AD external, forest, and realm trust configurations is not maintained, it is impossible to determine if the configurations are consistent with the intended security policy.'
  desc 'check', 'Start "Active Directory Domains and Trusts" (Available from various menus or run "domain.msc").
Select the left pane item that matches the name of the domain being reviewed.
Right-click the domain name and select "Properties".
Select the "Trusts" tab.

For each outbound and inbound external, forest, and realm trust, record the name of the other party (domain name), the trust type, transitivity, and the trust direction. (Keep this trust information for use in subsequent checks.)

Compare the list of trusts identified with documentation maintained by the ISSO.  

For each trust, the documentation must contain the following:
Type (external, forest, or realm)
Name of the other party
Confidentiality, Availability, and Integrity categorization
Classification level of the other party
Trust direction (inbound and/or outbound)
Transitivity
Status of the Selective Authentication option
Status of the SID filtering option

If an identified trust is not listed in the documentation or if any of the required items are not documented, this is a finding.'
  desc 'fix', 'Develop documentation for each AD external, forest, and realm trust configuration. At a minimum this must include:
Type (external, forest, or realm)
Name of the other party
Confidentiality, Availability, and Integrity categorization
Classification level of the other party
Trust direction (inbound and/or outbound)
Transitivity
Status of the Selective Authentication option
Status of the SID filtering option'
  impact 0.3
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-66399r1_chk'
  tag severity: 'low'
  tag gid: 'V-8530'
  tag rid: 'SV-30989r3_rule'
  tag stig_id: 'DS00.1120_AD'
  tag gtitle: 'Cross-Directory Authentication Documentation'
  tag fix_id: 'F-71787r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

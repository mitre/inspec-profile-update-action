control 'SV-213969' do
  title 'SQL Server must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of SQL Server. 
 
Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.   
 
The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A. 
 
NSA Type- (where =1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', 'In Windows, open Administrative Tools >> Local Security Policy. Expand Local Policies >> Security Options. In the right-side pane, find "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing."  
 
If, in the "Security Setting" column, the value is "Disabled," this is a finding. 
 
https://support.microsoft.com/en-us/kb/955720'
  desc 'fix', 'In Windows, open Administrative Tools >> Local Security Policy. Expand Local Policies >> Security Options. In the right-side pane, double-click on "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing."  
 
In the dialog box that appears, if the radio buttons are active, click "Enabled", and then click "Apply". If the radio buttons are grayed out, use Group Policy Management (on the appropriate server for this domain) to enforce the Enabled policy, and deploy it to the server(s) running SQL Server.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15186r313690_chk'
  tag severity: 'medium'
  tag gid: 'V-213969'
  tag rid: 'SV-213969r754614_rule'
  tag stig_id: 'SQL6-D0-008700'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-15184r313691_fix'
  tag 'documentable'
  tag legacy: ['SV-93905', 'V-79199']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end

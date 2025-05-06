control 'SV-30742' do
  title 'The database should be secured in accordance with DoD, vendor and/or commercially accepted practices where applicable.'
  desc "DBMS systems that do not follow DoD, vendor and/or public best security practices are vulnerable to related published vulnerabilities. A DoD reference document such as a security technical implementation guide or security recommendation guide constitutes the primary source for security configuration or implementation guidance for the deployment of newly acquired IA- and IA-enabled IT products that require use of the product's IA capabilities."
  desc 'check', 'Review security and administration documentation maintained for the DBMS system for indications that security guidance has been applied to the DBMS system.

If DoD security guidance is not available, the following are acceptable in descending order as available:
  (1) Commercially accepted practices (e.g., SANS);
  (2) Independent testing results (e.g., ICSA); or
  (3) Vendor literature

If the DBMS system has not been secured using available security guidance as listed above, this is a Finding.'
  desc 'fix', 'Apply available security guidance to the DBMS system.

If DoD security guidance is not available, the following are acceptable in descending order as available:
  (1) Commercially accepted practices (e.g., SANS);
  (2) Independent testing results (e.g., ICSA); or
  (3) Vendor literature'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-31152r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6767'
  tag rid: 'SV-30742r1_rule'
  tag stig_id: 'DG0007-ORACLE11'
  tag gtitle: 'DBMS security compliance'
  tag fix_id: 'F-27645r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end

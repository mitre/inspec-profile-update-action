control 'SV-25385' do
  title 'The DBMS should have configured all applicable settings to use trusted files, functions, features, or other components during startup, shutdown, aborts, or other unplanned interruptions.'
  desc 'The DBMS opens data files and reads configuration files at system startup, system shutdown and during abort recovery efforts. If the DBMS does not verify the trustworthiness of these files, it is vulnerable to malicious alterations of its configuration or unauthorized replacement of data.'
  desc 'check', 'Ask the DBA and/or IAO to demonstrate that the DBMS system initialization, shutdown, and aborts are configured to ensure that the DBMS system remains in a secure state.

If the DBA and/or IAO has documented proof from the DBMS vendor demonstrating that the DBMS does not support this either natively or programmatically, this check is a Finding, but can be downgraded to a CAT 3 severity.

If the DBMS does support this either natively or programmatically and the configuration does not meet the requirements listed above, this is a Finding.

For all MAC 1, all MAC 2 and Classified MAC 3 systems where the DBMS supports the requirements, review documented procedures and evidence of periodic testing to ensure DBMS system state integrity. 

If documented procedures do not exist or no evidence of implementation is provided, this is a Finding.'
  desc 'fix', 'Configure DBMS system initialization, shutdown and aborts to ensure DBMS system remains in a secure state.

For applicable DBMS systems as listed in the check, periodically test configuration to ensure DBMS system state integrity.

Where DBMS system state integrity is not supported by the DBMS vendor, obtain and apply mitigation strategies to bring risk to a DAA-acceptable level.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-28261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15649'
  tag rid: 'SV-25385r1_rule'
  tag stig_id: 'DG0155-ORACLE11'
  tag gtitle: 'DBMS System State Changes'
  tag fix_id: 'F-25690r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Database Administrator']
end

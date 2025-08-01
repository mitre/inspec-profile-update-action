control 'SV-24432' do
  title 'Access to DBMS security data should be audited.'
  desc 'DBMS security data is useful to malicious users to perpetrate activities that compromise DBMS operations or data integrity. Auditing of access to this data supports forensic and accountability investigations.'
  desc 'check', 'Determine the locations of DBMS audit, configuration, credential and other security data. Review audit settings for these files or data objects.

If access to the security data is not audited, this is a Finding.

If no access is audited, consider the operational impact and appropriateness for access that is not audited.

If the risk for incomplete auditing of the security files is reasonable and documented in the System Security Plan, then do not include this as a Finding.'
  desc 'fix', 'Determine all locations for storage of DBMS security and configuration data. Enable auditing for access to any security data. If auditing results in an unacceptable adverse impact on application operation, reduce the amount of auditing to a reasonable and acceptable level. Document any incomplete audit with acceptance of the risk of incomplete audit in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-23647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15643'
  tag rid: 'SV-24432r1_rule'
  tag stig_id: 'DG0140-ORACLE11'
  tag gtitle: 'DBMS security data access'
  tag fix_id: 'F-23926r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end

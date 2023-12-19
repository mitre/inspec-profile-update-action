control 'SV-24678' do
  title 'The DBMS should be periodically tested for vulnerability management and IA compliance.'
  desc 'The DBMS security configuration may be altered either intentionally or unintentionally over time. The DBMS may also be the subject of published vulnerabilities that require the installation of a security patch or a reconfiguration to mitigate the vulnerability. If the DBMS is not monitored for required or unintentional changes that render it not compliant with requirements, then it can be vulnerable to attack or compromise.'
  desc 'check', "Review procedures and evidence of implementation for DBMS IA and vulnerability management compliance.

This should include periodic, unannounced, in-depth monitoring and provide for specific penetration testing to ensure compliance with all vulnerability mitigation procedures such as the DoD IAVA or other DoD IA practices is planned, scheduled and conducted.

Testing is intended to ensure that the system's IA capabilities continue to provide adequate assurance against constantly evolving threats and vulnerabilities.

The results for Classified systems are required to be independently validated.

If the requirments listed above are not being met, this is a Finding."
  desc 'fix', 'Develop, document and implement procedures for periodic testing of the DBMS for current vulnerability management and security configuration compliance as stated in the check.

Coordinate 3rd-party validation testing for Classified systems.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29194r1_chk'
  tag severity: 'low'
  tag gid: 'V-15112'
  tag rid: 'SV-24678r1_rule'
  tag stig_id: 'DG0088-ORACLE11'
  tag gtitle: 'DBMS vulnerability mgmt and IA compliance testing'
  tag fix_id: 'F-26210r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end

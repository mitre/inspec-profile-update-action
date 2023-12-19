control 'SV-24691' do
  title 'Plans and procedures for testing DBMS installations, upgrades and patches should be defined and followed prior to production implementation.'
  desc 'Updates and patches to existing software have the intention of improving the security or enhancing or adding features to the product. However, it is unfortunately common that updates or patches can render production systems inoperable or even introduce serious vulnerabilities. Some updates also set security configurations back to unacceptable settings that do not meet security requirements. For these reasons, it is a good practice to test updates and patches offline before introducing them in a production environment.'
  desc 'check', 'Review policy and procedures documented or noted in the System Security Plan and evidence of implementation for testing DBMS installations, upgrades and patches prior to production deployment.

If policy and procedures do not exist or evidence of implementation does not exist, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures for testing DBMS installations, upgrades and patches prior to deployment on production systems.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15139'
  tag rid: 'SV-24691r1_rule'
  tag stig_id: 'DG0097-ORACLE11'
  tag gtitle: 'DBMS testing plans and procedures'
  tag fix_id: 'F-26256r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end

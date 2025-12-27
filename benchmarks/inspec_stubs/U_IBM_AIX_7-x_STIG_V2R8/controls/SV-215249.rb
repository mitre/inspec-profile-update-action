control 'SV-215249' do
  title 'AIX audit tools must be group-owned by audit.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', %q(Check the following audit tools are group-owned by "audit":

    /usr/sbin/audit
    /usr/sbin/auditbin
    /usr/sbin/auditcat
    /usr/sbin/auditconv
    /usr/sbin/auditmerge
    /usr/sbin/auditpr
    /usr/sbin/auditselect
    /usr/sbin/auditstream

# ls -l /usr/sbin/audit*|grep -v ldap
-r-sr-x---    1 root     audit         64926 Mar 30 2016  /usr/sbin/audit
-r-sr-x---    1 root     audit         41240 Mar 30 2016  /usr/sbin/auditbin
-r-sr-x---    1 root     audit         40700 Mar 30 2016  /usr/sbin/auditcat
-r-sr-x---    1 root     audit         13072 Mar 30 2016  /usr/sbin/auditconv
-r-sr-x---    1 root     audit         11328 Mar 30 2016  /usr/sbin/auditmerge
-r-sr-x---    1 root     audit         53466 Mar 30 2016  /usr/sbin/auditpr
-r-sr-x---    1 root     audit         33128 Mar 30 2016  /usr/sbin/auditselect
-r-sr-x---    1 root     audit         29952 Mar 30 2016  /usr/sbin/auditstream

If any above file's are not group-owned by "audit", this is a finding. 

Verify that "/usr/sbin/auditldap" group-owned by "security":

# ls -l /usr/sbin/auditldap
-r-x------    1 root     security      12204 Mar 30 2016  /usr/sbin/auditldap

If the group-owner of "/usr/sbin/auditldap" is not "security", this is a finding.)
  desc 'fix', 'For each audit tool in: 
   /usr/sbin/audit
    /usr/sbin/auditbin
    /usr/sbin/auditcat
    /usr/sbin/auditconv
    /usr/sbin/auditmerge
    /usr/sbin/auditpr
    /usr/sbin/auditselect
    /usr/sbin/auditstream

Set the group to "audit".  
# chgrp audit <audit tool>

For  /usr/sbin/auditldap:

Set the group to "security". 
# chgrp security  /usr/sbin/auditldap'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16447r294198_chk'
  tag severity: 'medium'
  tag gid: 'V-215249'
  tag rid: 'SV-215249r508663_rule'
  tag stig_id: 'AIX7-00-002026'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-16445r294199_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag legacy: ['V-91469', 'SV-101567']
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end

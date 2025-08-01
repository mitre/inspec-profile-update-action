control 'SV-221471' do
  title 'OHS must not have the directive PlsqlDatabasePassword set in clear text.'
  desc 'OHS supports the use of the module mod_plsql, which allows applications to be hosted that are PL/SQL-based.  To access the database, the module must have a valid username, password and database name.  To keep the password from an attacker, the password must not be stored in plain text, but instead, obfuscated.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., dads.conf) included in it with an editor.

2. Search for the "PlsqlDatabasePassword" directive.

3. If the directive is set in clear text, this is a finding.'
  desc 'fix', '1. At shell prompt, set "ORACLE_HOME" environment variable to $ORACLE_HOME location and export the variable.

2. At shell prompt, set "PATH" environment variable to "$ORACLE_HOME/ohs/bin:$ORACLE_HOME/bin:$ORACLE_HOME/perl/bin:$PATH" and export the variable.

3a. If AIX OS, at shell prompt, set "LIBPATH" environment variable to "$ORACLE_HOME/lib:$LIBPATH" and export the variable.
3b. If HP-UX OS, at shell prompt, set "SHLIB_PATH" environment variable to "$ORACLE_HOME/lib:$SHLIB_PATH" and export the variable.
3c. If Solaris OS, at shell prompt, set "LD_LIBRARY_PATH" environment variable to "$ORACLE_HOME/lib32:$LD_LIBRARY_PATH" and export the variable.
3d. If Linux or Other Unix OS, at shell prompt, set "LD_LIBRARY_PATH" environment variable to "$ORACLE_HOME/lib:$LD_LIBRARY_PATH" and export the variable.

4. Change the present working directory to "$ORACLE_HOME/ohs/bin" (e.g., cd $ORACLE_HOME/ohs/bin).

5. For each .conf file found to be at fault, execute dadTool.pl script (e.g., "perl dadTool.pl -f $DOMAIN_HOME/config/fmwconfig/compoennts/OHS/<componentName>/mod_plsql/dads.conf").'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23186r415096_chk'
  tag severity: 'high'
  tag gid: 'V-221471'
  tag rid: 'SV-221471r879887_rule'
  tag stig_id: 'OH12-1X-000234'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23175r415097_fix'
  tag 'documentable'
  tag legacy: ['SV-79111', 'V-64621']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

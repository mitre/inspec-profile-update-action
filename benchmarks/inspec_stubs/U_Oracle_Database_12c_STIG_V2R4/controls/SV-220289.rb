control 'SV-220289' do
  title 'The DBMS must support the organizational requirements to specifically prohibit or restrict the use of unauthorized functions, ports, protocols, and/or services.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Additionally, it is sometimes convenient to provide multiple services from a single component of an information system (e.g., email and web services), but doing so increases risk by constraining the ability to restrict the use of functions, ports, protocols, and/or services.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'Review the DBMS settings for functions, ports, protocols, and services that are not approved.

If any are found, this is a finding.

(For definitive information on Ports, Protocols, and Services Management [PPSM], refer to https://cyber.mil/ppsm/)

- - - - -
In the Oracle database, the communications with the database and incoming requests are performed by the Oracle Listener. The Oracle Listener listens on a specific port or ports for connections to a specific database. The Oracle Listener has configuration files located in the $ORACLE_HOME/network/admin directory. To check the ports and protocols in use, go to  that directory and review the SQLNET.ora, LISTENER.ora, and the TNSNAMES.ora. If protocols or ports are in use that are not authorized, this is a finding.'
  desc 'fix', 'Disable functions, ports, protocols, and services that are not approved.

- - - - -
Change the SQLNET.ora, LISTENER.ora, and TNSNAMES.ora files to reflect the proper use of ports, protocols, and services that are approved at the site.

If changes to the Listener are made, the files associated with the Listener must be reloaded. Do that by issuing the following commands at the UNIX/Linux or Windows prompt.
Issue the command to see what the current status is:
$ lsnrctl stat
Load the new file that was corrected to reflect site-specific requirements.
$ lsnrctl reload
Check the status again to see that the changes have taken place.
$ lsnrctl stat'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22004r822473_chk'
  tag severity: 'medium'
  tag gid: 'V-220289'
  tag rid: 'SV-220289r822475_rule'
  tag stig_id: 'O121-C2-011900'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-21996r822474_fix'
  tag 'documentable'
  tag legacy: ['SV-76177', 'V-61687']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

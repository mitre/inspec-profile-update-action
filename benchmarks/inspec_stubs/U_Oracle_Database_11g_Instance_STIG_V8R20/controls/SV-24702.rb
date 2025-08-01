control 'SV-24702' do
  title 'DBMS processes or services should run under custom, dedicated OS accounts.'
  desc 'Shared accounts do not provide separation of duties nor allow for assignment of least privileges for use by database processes and services. Without separation and least privilege, the exploit of one service or process is more likely to be able to compromise another or all other services.'
  desc 'check', 'Ask the DBA/SA to demonstrate process ownership for the Oracle DBMS software.

On UNIX Systems (enter at command prompt):

ps ef | grep -i pmon | grep -v grep (all database processes)
ps ef | grep -i tns | grep -v grep (all listener processes)
ps ef | grep -i dbsnmp | grep -v grep (Oracle Intelligent Agents)

Sample output (database processes):

oracle 5593 1 0 08:15 ? 00:00:00 ora_pmon_oraprod1

Sample output (listener processes):

oracle 5505 1 0 08:15 ? 00:00:00 /var/opt/oracle/product/10.2.0/db_1/bin/tnslsnr LISTENER -inherit

Sample output (agent processes):

oracle 1734 1 0 08:16 ? 00:00:00 /var/opt/oracle/product/10.2.0/db_1/bin/dbsnmp

In the above samples, the occurrence of "oracle" indicate the user account that owns the process.

If any Oracle processes are not using a dedicated OS account, this is a Finding.

For Windows Systems:

Log in using account with administrator privileges.

Open the Services snap-in.

Review the Oracle processes.

All Oracle processes should be run (Log On As) by a dedicated Oracle Windows OS account and not as LocalSystem.

If any Oracle service is not run by a dedicated Oracle Windows OS account, this is a Finding.

If any Oracle service is run as LocalSystem, this is a Finding.'
  desc 'fix', 'On UNIX Systems:

Ensure the Oracle Owner account is used for all Oracle processes.

The Oracle SNMP agent (Intelligent or Management Agent) is required (by Oracle Corp per MetaLink Note 548928.1) to use the Oracle Process owner account.

On Windows Systems:

Create and assign a dedicated Oracle Windows OS account for all Oracle processes.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29295r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15141'
  tag rid: 'SV-24702r2_rule'
  tag stig_id: 'DG0102-ORACLE11'
  tag gtitle: 'DBMS services dedicated custom account'
  tag fix_id: 'F-26327r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end

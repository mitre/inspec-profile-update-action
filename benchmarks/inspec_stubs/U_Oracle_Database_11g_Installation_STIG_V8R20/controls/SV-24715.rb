control 'SV-24715' do
  title 'The DBMS should not be operated without authorization on a host system supporting other application services.'
  desc "In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system. A DBMS not installed on a dedicated host is threatened by other hosted applications. Applications that share a single DBMS may also create risk to one another. Access controls defined for one application by default may provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'Review a list of Windows service or UNIX processes running on the DBMS host.

For Windows, review the Services snap-in.

Investigate with the DBA/SA any unknown services.

For UNIX, issue the ps -ef command.

Investigate with the DBA/SA any unknown processes.

If web, application, ftp, domain, print or other non-DBMS services or processes are identified as supporting other optional applications or functions not authorized in the System Security Plan, this is a Finding.

NOTE:  Only applications that are technically required to share the same host system may be authorized to do so. Applications that share the same host for administrative, financial or other non-technical reasons may not be authorized and are a Finding.'
  desc 'fix', 'A dedicated host system in this case refers to an instance of the operating system at a minimum.

The operating system may reside on a virtual host machine where supported by the DBMS vendor.

Remove any unauthorized processes or services and install on a separate host system.

Where separation is not supported, update the System Security Plan to provide the technical requirement for having the application share a host with the DBMS.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29349r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15146'
  tag rid: 'SV-24715r1_rule'
  tag stig_id: 'DG0109-ORACLE11'
  tag gtitle: 'DBMS dedicated host'
  tag fix_id: 'F-26374r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end

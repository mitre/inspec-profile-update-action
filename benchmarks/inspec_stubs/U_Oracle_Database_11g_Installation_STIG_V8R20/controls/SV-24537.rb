control 'SV-24537' do
  title 'Connections by mid-tier web and application systems to the Oracle DBMS should be protected, encrypted and authenticated according to database, web, application, enclave and network requirements.'
  desc 'Multi-tier systems may be configured with the database and connecting middle-tier system located on an internal network, with the database located on an internal network behind a firewall and the middle-tier system located in a DMZ. In cases where systems are located in the DMZ, network communications between both systems must be encrypted. In all cases, the application account requires PKI authentication. IP address restriction to the backend database system, under a separate requirement, provides an additional level of protection.'
  desc 'check', 'Review the System Security Plan for remote applications that access and use the database.

If none of the applications accessing the database uses a single account for access by multiple persons or processes, this check is Not a Finding.

Verify that the application account uses PKI authentication:

From SQL*Plus:
select name, ext_username from user$ where ext_username is not null;

If the ext_username indicates a directory name, then verify that the directory name is authenticated using PKI.

You may require the DBA or directory server administrator to display the username definition in the directory service to you.

If the ext_username does not specify a certificate or PKI-authenticated user account, this is a Finding.'
  desc 'fix', 'Configure PKI authentication to help protect access to the shared account.

PKI authentication may be accomplished using Oracle Advanced Security on most platforms.

On a Windows host, user authentication using PKI may be used with Active Directory or NTS authentication using the DoD CAC.

On UNIX and other hosts, Oracle Advanced Security may be used to authenticate via LDAP or SSL.

The application may require storage of the authentication certificate in the Oracle Wallet or on a hardware security module (HSM) to authenticate.

Please see the Oracle Security Guides and the Oracle Advanced Security Guides for instructions on configuring PKI authentication.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29453r3_chk'
  tag severity: 'medium'
  tag gid: 'V-3440'
  tag rid: 'SV-24537r3_rule'
  tag stig_id: 'DO0360-ORACLE11'
  tag gtitle: 'DBMS mid-tier application account access'
  tag fix_id: 'F-26517r2_fix'
  tag responsibility: ['Information Assurance Officer', 'Database Administrator']
end

control 'SV-237700' do
  title 'The DBMS must support the disabling of network protocols deemed by the organization to be nonsecure.'
  desc 'This requirement is related to remote access, but more specifically to the networking protocols allowing systems to communicate. Remote access is any access to an organizational information system by a user (or an information system) communicating through an external, non-organization controlled network (e.g., the internet). Examples of remote access methods include dial-up, broadband, and wireless.

Some networking protocols allowing remote access may not meet security requirements to protect data and components. Bluetooth and peer-to-peer networking are examples of less than secure networking protocols.

The DoD Ports, Protocols, and Services Management (PPSM) program provides implementation guidance on the use of IP protocols and application and data services traversing the DoD Networks in a manner supporting net-centric operations.

Applications implementing or utilizing remote access network protocols need to ensure the application is developed and implemented in accordance with the PPSM requirements. In situations where it has been determined that specific operational requirements outweigh the risks of enabling an insecure network protocol, the organization may pursue a risk acceptance.

Using protocols deemed nonsecure would compromise the ability of the DBMS to operate in a secure fashion. The database must be able to disable network protocols deemed nonsecure.'
  desc 'check', %q(Review the PPSM Technical Assurance List to acquire an up-to-date list of network protocols deemed nonsecure.
(For definitive information on Ports, Protocols, and Services Management (PPSM), refer to https://cyber.mil/ppsm/)

Review DBMS settings to determine if the database is utilizing any network protocols deemed nonsecure. If the DBMS is not using any network protocols deemed nonsecure, this is not a finding.

If the database is utilizing protocols specified as nonsecure in the PPSM, verify the protocols are explicitly identified in the System Security Plan (SSP) and that they are in support of specific operational requirements. If they are not identified in the SSP or are not supporting specific operational requirements, this is a finding.

If nonsecure network protocols are not being used but are not disabled in the DBMS's configuration, this is a finding.

After determining the site-specific operational requirements and the protocols explicitly defined in the SSP, check the $TNS_ADMIN setting for the location of the Oracle listener.ora file. The listener.ora file is a configuration file for Oracle Net Listener that identifies the following:

A unique name for the listener, typically LISTENER
A protocol address that it is accepting connection requests on, and
A service it is listening for.

If the listener.ora file shows a PROTOCOL= statement and the PROTOCOL is deemed nonsecure, that is a finding.

LISTENER=
  (DESCRIPTION=
    (ADDRESS_LIST=
      (ADDRESS=(PROTOCOL=tcp)(HOST=sale-server)(PORT=1521))
      (ADDRESS=(PROTOCOL=ipc)(KEY=extproc))))
SID_LIST_LISTENER=
  (SID_LIST=
    (SID_DESC=
      (GLOBAL_DBNAME=sales.us.example.com)
      (ORACLE_HOME=/oracle12c)
      (SID_NAME=sales))
    (SID_DESC=
      (SID_NAME=plsextproc)
      (ORACLE_HOME=/oracle12c)
      (PROGRAM=extproc)))

Protocol Parameters

The Oracle Listener and the Oracle Connection Manager are identified by protocol addresses. The information below contains the "Protocol-Specific Parameters" used by the Oracle protocol support.

Protocol-Specific Parameters

Protocol: IPC     Parameter: PROTOCOL  Notes: Specify ipc as the value.
Protocol: IPC     Parameter: KEY       Notes: Specify a unique name for the service. Oracle recommends using the service name or SID of the service.
Example: (PROTOCOL=ipc)(KEY=sales)

Protocol: Named Pipes  Parameter: PROTOCOL  Notes: Specify nmp as the value.
Protocol: Named Pipes  Parameter: SERVER    Notes: Specify the name of the Oracle server.
Protocol: Named Pipes  Parameter: PIPE      Notes: Specify the pipe name used to connect to the database server.
This is the same PIPE keyword specified on the server with Named Pipes.  This name can be any name.
Example: (Protocol=nmp) (SERVER=USDOD) (PIPE=dbpipe01)
            
Protocol: SDP     Parameter: PROTOCOL  Notes: Specify sdp as the value.
Protocol: SDP     Parameter: HOST      Notes: Specify the host name or IP address of the computer.
Protocol: SDP     Parameter: PORT      Notes: Specify the listening port number.
Example: (PROTOCOL=sdp)(HOST=sales-server)(PORT=1521)
         (PROTOCOL=sdp)(HOST=192.168.2.204)(PORT=1521)

Protocol: TCP/IP  Parameter: PROTOCOL  Notes: Specify TCP as the value.
Protocol: TCP/IP  Parameter: HOST      Notes: Specify the host name or IP address of the computer.
Protocol: TCP/IP  Parameter: PORT      Notes: Specify the listening port number.
Example: (PROTOCOL=tcp)(HOST=sales-server)(PORT=1521)
         (PROTOCOL=tcp)(HOST=192.168.2.204)(PORT=1521)
 
Protocol: TCP/IP with TLS  Parameter: PROTOCOL  Notes: Specify tcps as the value.
Protocol: TCP/IP with TLS  Parameter: HOST      Notes: Specify the host name or IP address of the computer.
Protocol: TCP/IP with TLS  Parameter: PORT      Notes: Specify the listening port number.
                                                        Example:(PROTOCOL=tcps)(HOST=sales-server) (PORT=2484)
        (PROTOCOL=tcps)(HOST=192.168.2.204)(PORT=2484))
  desc 'fix', 'Disable any network protocol listed as nonsecure in the PPSM documentation.

To disable the protocol deemed not secure, stop the listener by issuing the following command as the Oracle Software owner, typically Oracle:
          $ lsnrctl stop
This will stop the listener. Edit the LISTENER.ORA file and remove the protocols deemed not secure and restart the listener.

For example, if TCP was deemed as not secure, the listener.ora would need to be changed and the tcp entry would need to be removed. That would only allow the listener to listen for an IPC connection.

LISTENER=
  (DESCRIPTION=
    (ADDRESS_LIST=
      (ADDRESS=(PROTOCOL=tcp)(HOST=sale-server)(PORT=1521)) - remove this line and properly balance the parentheses -
      (ADDRESS=(PROTOCOL=ipc)(KEY=extproc))))
SID_LIST_LISTENER=
  (SID_LIST=
    (SID_DESC=
      (GLOBAL_DBNAME=sales.us.example.com)
      (ORACLE_HOME=/oracle12c)
      (SID_NAME=sales))
    (SID_DESC=
      (SID_NAME=plsextproc)
      (ORACLE_HOME=/oracle12c)
      (PROGRAM=extproc)))

Revise the client side TNSNAMES.ORA to align the PROTOCOL value in the PROTOCOL portion of the connect string. For example, if TCP was deemed as not secure and the listener.ora was changed to listen for an IPC connection the code below would be required:

net_service_name=
(DESCRIPTION=
(ADDRESS=(PROTOCOL=tcp)(HOST=sales1-svr)(PORT=1521))
(ADDRESS=(PROTOCOL=tcp)(HOST=sales2-svr)(PORT=1521))
(CONNECT_DATA=
(SERVICE_NAME=sales.us.example.com)))'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40919r822484_chk'
  tag severity: 'medium'
  tag gid: 'V-237700'
  tag rid: 'SV-237700r822486_rule'
  tag stig_id: 'O121-C2-001700'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-40882r822485_fix'
  tag 'documentable'
  tag legacy: ['V-61555', 'SV-76045']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

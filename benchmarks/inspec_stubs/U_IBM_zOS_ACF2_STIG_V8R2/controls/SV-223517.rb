control 'SV-223517' do
  title 'IBM z/OS SMF recording options for the FTP Server must be configured to write SMF records for all eligible events.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.

SMF data collection is the basic unit of tracking of all system functions and actions. Included in this tracking data are the audit records from each of the ACPs and system. If the required SMF data record types are not being collected, then accountability cannot be monitored, and its use in the execution of a contingency plan could be compromised.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.

'
  desc 'check', 'Refer to the FTP.DATA file specified on the SYSFTPD DD statement in the FTP started task JCL. The SYSFTPD DD statement is optional. The search order for FTP.DATA is: 
 /etc/ftp.data 
 SYSFTPD DD statement 
 jobname.FTP.DATA 
 SYS1.TCPPARMS(FTPDATA) 
 tcpip.FTP.DATA 

If FTPDATA is configured with the following SMF statements, this is not a finding.

FTP.DATA Configuration Statements
SMF TYPE119
SMFJES TYPE119
SMFSQL TYPE119
SMFAPPE [Not coded or commented out]
SMFDEL [Not coded or commented out]
SMFEXIT [Not coded or commented out]
SMFLOGN [Not coded or commented out]
SMFREN [Not coded or commented out]
SMFRETR [Not coded or commented out]
SMFSTOR [Not coded or commented out]'
  desc 'fix', 'Configure SMF options to conform to the specifications in the FTPDATA Configuration Statements below or that they are commented out.

SMF TYPE119
SMFJES TYPE119
SMFSQL TYPE119
SMFAPPE [Not coded or commented out]
SMFDEL [Not coded or commented out]
SMFEXIT [Not coded or commented out]
SMFLOGN [Not coded or commented out]
SMFREN [Not coded or commented out]
SMFRETR [Not coded or commented out]
SMFSTOR [Not coded or commented out]

The FTP Server can provide audit data in the form of SMF records. SMF record type 119, the TCP/IP Statistics record, can be written with the following subtypes:

70 – Append
70 – Delete and Multiple Delete
72 – Invalid Logon Attempt
70 – Rename
70 – Get (Retrieve) and Multiple Get
70 – Put (Store and Store Unique) and Multiple Put

SMF data produced by the FTP Server provides transaction information for both successful and unsuccessful FTP commands. This data may provide valuable information for security audit activities. Type 119 records use a more standard format and provide more information.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25190r504615_chk'
  tag severity: 'medium'
  tag gid: 'V-223517'
  tag rid: 'SV-223517r533198_rule'
  tag stig_id: 'ACF2-FT-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25178r504616_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['V-97739', 'SV-106843']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end

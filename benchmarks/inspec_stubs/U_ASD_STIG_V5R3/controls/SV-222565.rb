control 'SV-222565' do
  title 'The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as, system configuration details, diagnostic information, user information, and potentially sensitive application data.

Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application maintenance functions.

If the application does not provide non-local maintenance and diagnostic capability, this requirement is not applicable.

Identify the maintenance functions/capabilities that are provided by the application, performed by an individual/admin and which can be performed remotely.

Examples include but are not limited to:

The application may provide the ability to clean up a folder of temporary files, add users, remove users, restart processes, backup certain files, manage logs, or execute diagnostic sessions.

Have the application admin authenticate to the application in an administrative role and verify that strong credentials (CAC) are required to access when performing application maintenance.

Have the application admin authenticate to the application host OS and verify that strong credentials (CAC) are required to access when performing application maintenance.

If the application administrator is prevented from accessing the OS by policy requirement or separation of duties requirements, this is not a finding.

If a CAC is not used when remotely accessing the application for maintenance or diagnostic sessions, this is a finding.'
  desc 'fix', 'Configure the application to use strong authentication (CAC) when accessing the application for maintenance purposes.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24235r493603_chk'
  tag severity: 'medium'
  tag gid: 'V-222565'
  tag rid: 'SV-222565r879620_rule'
  tag stig_id: 'APSC-DV-001970'
  tag gtitle: 'SRG-APP-000185'
  tag fix_id: 'F-24224r493604_fix'
  tag 'documentable'
  tag legacy: ['SV-84803', 'V-70181']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end

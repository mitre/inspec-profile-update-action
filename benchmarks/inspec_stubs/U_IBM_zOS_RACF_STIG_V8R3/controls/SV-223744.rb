control 'SV-223744' do
  title 'IBM z/OS startup parameters for the FTP server must have the INACTIVE statement properly set.'
  desc 'To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Refer to the FTPD started task procedure.

If the SYSTCPD and SYSFTPD DD statements specify the TCP/IP Data and FTP Data configuration files respectively, this is not a finding.

If the ANONYMOUS keyword is not coded on the PARM parameter on the EXEC statement, this is not a finding.

If the ANONYMOUS=logonid combination is not coded on the PARM parameter on the EXEC statement, this is not a finding.

If the INACTIVE keyword is not coded on the PARM parameter on the EXEC statement, this is not a finding.'
  desc 'fix', 'Review the FTP daemon’s started task JCL. Ensure that the ANONYMOUS and INACTIVE startup parameters are not specified and configuration file names are specified on the appropriate DD statements.

The FTP daemon program can accept parameters in the JCL procedure that is used to start the daemon. The ANONYMOUS and ANONYMOUS= keywords are designed to allow anonymous FTP connections. The INACTIVE keyword is designed to set the timeout value for inactive connections. Control of these options is recommended through the configuration file statements rather than the startup parameters.

The systems programmer responsible for supporting ICS will ensure that the startup parameters for the FTP daemon does not include the ANONYMOUS, ANONYMOUS=, or INACTIVE keywords.

During initialization the FTP daemon searches multiple locations for the TCPIP.DATA and FTP.DATA files according to fixed sequences. In the daemon’s started task JCL, Data Definition (DD) statements will be used to specify the locations of the files. The SYSTCPD DD statement identifies the TCPIP.DATA file and the SYSFTPD DD statement identifies the FTP.DATA file.

The systems programmer responsible for supporting ICS will ensure that the FTP daemon’s started task JCL specifies the SYSTCPD and SYSFTPD DD statements for configuration files.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25417r514920_chk'
  tag severity: 'medium'
  tag gid: 'V-223744'
  tag rid: 'SV-223744r604139_rule'
  tag stig_id: 'RACF-FT-000120'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25405r514921_fix'
  tag 'documentable'
  tag legacy: ['V-98195', 'SV-107299']
  tag cci: ['CCI-001133', 'CCI-000804']
  tag nist: ['SC-10', 'IA-8']
end

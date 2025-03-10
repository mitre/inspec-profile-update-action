control 'SV-223981' do
  title 'IBM z/OS startup parameters for the FTP server must have the INACTIVE statement properly set.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', "Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

If all the items below are true, this is not a finding.

If any of the items below are untrue, this is a finding.

The following items are in effect for the FTP daemon's started task JCL:

-The SYSTCPD and SYSFTPD DD statements specify the TCP/IP Data and FTP Data configuration files respectively.
-The ANONYMOUS keyword is not coded on the PARM parameter on the EXEC statement.
-The ANONYMOUS=logonid combination is not coded on the PARM parameter on the EXEC statement.
-The INACTIVE keyword is not coded on the PARM parameter on the EXEC statement.

The AUTOLOG statement block can be configured to have TCP/IP start the FTP Server. The FTP entry (e.g., FTPD) can include the PARMSTRING parameter to pass parameters to the FTP procedure when started.

NOTE: Parameters passed on the PARMSTRING parameter override parameters specified in the FTP procedure.

If an FTP entry is configured in the AUTOLOG statement block in the TCP/IP Profile configuration file, ensure the following items are in effect:

-The ANONYMOUS keyword is not coded on the PARMSTRING parameter.
-The ANONYMOUS=logonid combination is not coded on the PARMSTRING parameter.
-The INACTIVE keyword is not coded on PARMSTRING parameter."
  desc 'fix', "Review the FTP daemon's started task JCL. Ensure that the ANONYMOUS and INACTIVE startup parameters are not specified and configuration file names are specified on the appropriate DD statements.

The FTP daemon program can accept parameters in the JCL procedure that is used to start the daemon. The ANONYMOUS and ANONYMOUS= keywords are designed to allow anonymous FTP connections. The INACTIVE keyword is designed to set the timeout value for inactive connections. Control of these options is recommended through the configuration file statements rather than the startup parameters.

The systems programmer responsible for supporting ICS will ensure that the startup parameters for the FTP daemon does not include the ANONYMOUS, ANONYMOUS=, or INACTIVE keywords.

During initialization the FTP daemon searches multiple locations for the TCPIP.DATA and FTP.DATA files according to fixed sequences. In the daemon's started task JCL, Data Definition (DD) statements will be used to specify the locations of the files. The SYSTCPD DD statement identifies the TCPIP.DATA file and the SYSFTPD DD statement identifies the FTP.DATA file.

The systems programmer responsible for supporting ICS will ensure that the FTP daemon's started task JCL specifies the SYSTCPD and SYSFTPD DD statements for configuration files."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25654r868969_chk'
  tag severity: 'medium'
  tag gid: 'V-223981'
  tag rid: 'SV-223981r877822_rule'
  tag stig_id: 'TSS0-FT-000090'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-25642r868970_fix'
  tag 'documentable'
  tag legacy: ['SV-107773', 'V-98669']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

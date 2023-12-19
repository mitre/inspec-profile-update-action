control 'SV-223735' do
  title 'IBM z/OS data sets for the FTP server must be properly protected.'
  desc 'MVS data sets of the FTP Server provide the configuration and operational characteristics of this product. Failure to properly secure these data sets may lead to unauthorized access resulting in the compromise of the integrity and availability of customer data and some system services.'
  desc 'check', 'Refer to the FTP server Started task (usually FTPD). Refer to the dataset defined on the SYSFTPD DD statement.

If WRITE and ALLOCATE access to the data set containing the FTP Data configuration file is restricted to systems programming personnel, this is not a finding.

Note: READ access to all authenticated users is permitted.

If WRITE and ALLOCATE access to the data set containing the FTP Data configuration file is logged, this is not a finding.

If WRITE and ALLOCATE access to the data set containing the FTP banner file is restricted to systems programming personnel, this is not a finding.

Note: READ access to the data set containing the FTP banner file is permitted to all authenticated users.

Notes: The MVS data sets mentioned above are not used in every configuration. Absence of a data set will not be considered a finding. The data set containing the FTP Data configuration file is determined by checking the SYSFTPD DD statement in the FTP started task JCL. The data set containing the FTP banner file is determined by checking the BANNER statement in the FTP Data configuration file.'
  desc 'fix', 'Review the data set access authorizations defined to the ACP for the FTP.DATA and FTP.BANNER files. Configure these data sets to be protected as follows:

The data set containing the FTP.DATA configuration file allows read access to all authenticated users and all other access is restricted to systems programming personnel.

All Write and Allocate access to the data set containing the FTP.DATA configuration file is logged.

The data set containing the FTP banner file allows read access to all authenticated users and all other access is restricted to systems programming personnel.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25408r514893_chk'
  tag severity: 'medium'
  tag gid: 'V-223735'
  tag rid: 'SV-223735r604139_rule'
  tag stig_id: 'RACF-FT-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25396r514894_fix'
  tag 'documentable'
  tag legacy: ['V-98177', 'SV-107281']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

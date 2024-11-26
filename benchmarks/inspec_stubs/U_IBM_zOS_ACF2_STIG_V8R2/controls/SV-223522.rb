control 'SV-223522' do
  title 'IBM z/OS FTP.DATA configuration statements for the FTP Server must specify the BANNER statement.'
  desc 'The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.'
  desc 'check', 'Refer to the Data configuration file specified on the SYSFTPD DD statement in the FTP started task JCL.

If the BANNER statement is coded, this is not a finding.'
  desc 'fix', 'Configure the FTP.DATA CONFIGURATION STATEMENT to include the following:

BANNER [An HFS file, e.g., /etc/ftp.banner]'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25195r500700_chk'
  tag severity: 'medium'
  tag gid: 'V-223522'
  tag rid: 'SV-223522r533198_rule'
  tag stig_id: 'ACF2-FT-000060'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25183r500701_fix'
  tag 'documentable'
  tag legacy: ['SV-106853', 'V-97749']
  tag cci: ['CCI-001388', 'CCI-001387', 'CCI-001385', 'CCI-001386', 'CCI-001384']
  tag nist: ['AC-8 c 3', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 1']
end

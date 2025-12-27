control 'SV-223650' do
  title 'IBM RACF must limit Write or greater access to libraries that contain PPT modules to system programmers only.'
  desc 'Specific PPT designated program modules possess significant security bypass capabilities. Unauthorized access could result in the compromise of the operating system environment, ACP, and customer data.

'
  desc 'check', 'Review program entries in the IBM Program Properties Table (PPT). You may use a third-party product to examine these entries however, to determine program entries issue the following command from an ISPF command line:
TSO ISRDDN LOAD IEFSDPPT
Press Enter.

For each module identified in the "eyecatcher" if all of the following are untrue, this is not a finding.

If any of the following is true, this is a finding.

-The ACP data set rules for libraries that contain PPT modules do not restrict WRITE or greater access to only z/OS systems programming personnel.
-The ACP data set rules for libraries that contain PPT modules do not specify that all WRITE or greater access will be logged.'
  desc 'fix', 'Configure the WRITE or greater access to libraries containing PPT modules to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.3
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25323r514639_chk'
  tag severity: 'low'
  tag gid: 'V-223650'
  tag rid: 'SV-223650r853568_rule'
  tag stig_id: 'RACF-ES-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25311r514640_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98005', 'SV-107109']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end

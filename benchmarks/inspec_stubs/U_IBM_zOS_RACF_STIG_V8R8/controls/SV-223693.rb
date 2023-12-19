control 'SV-223693' do
  title 'The IBM z/OS JES(XBMALLRACF) SETROPTS value must be set to JES(XBMALLRACF).'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the JES(XBMALLRACF) is enabled then the message "JES-XBMALLRACF OPTION IS ACTIVE" will be displayed, this is not a finding.

If the message "JES-XBMALLRACF OPTION IS INACTIVE" is displayed, this is a finding.'
  desc 'fix', 'Configure JES(XBMALLRACF) SETROPTS value to be set to JES(XBMALLRACF). This specifies that JES is set to test for a userid and password on the job statement or for propagated RACF identification information for all jobs run under the execution batch monitor.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a status of JES-XBMALLRACF. 

XBMALLRACF is activated with the command SETR XBMALLRACF.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25366r514767_chk'
  tag severity: 'medium'
  tag gid: 'V-223693'
  tag rid: 'SV-223693r853599_rule'
  tag stig_id: 'RACF-ES-000460'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-25354r514768_fix'
  tag 'documentable'
  tag legacy: ['SV-107197', 'V-98093']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end

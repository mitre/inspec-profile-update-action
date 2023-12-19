control 'SV-223692' do
  title 'The IBM RACF JES(BATCHALLRACF) SETROPTS value must be set to JES(BATCHALLRACF).'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'From ISPF Command Shell enter: 
SETRopts List

If the JES(BATCHALLRACF) is enabled then the message "JES-BATCHALLRACF OPTION IS ACTIVE" will be displayed, this is not a finding.

If the message "JES-BATCHALLRACF OPTION IS INACTIVE" is displayed, this is a finding.'
  desc 'fix', 'Configure JES(BATCHALLRACF) SETROPTS value to be set to JES(BATCHALLRACF). This specifies that JES is to test for a userid and password on the job statement or for propagated RACF identification information for all batch jobs.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a status of JES BATCHALLRACF. 

JES BATCHALLRACF is activated with the command SETR JES(BATCHALLRACF).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25365r514764_chk'
  tag severity: 'medium'
  tag gid: 'V-223692'
  tag rid: 'SV-223692r604139_rule'
  tag stig_id: 'RACF-ES-000440'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-25353r514765_fix'
  tag 'documentable'
  tag legacy: ['SV-107193', 'V-98089']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end

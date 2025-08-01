control 'SV-223712' do
  title 'IBM z/OS Batch job user IDs must be properly defined.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Refer to the documentation of the processes used for submission of batch jobs via an automated process (i.e., scheduler or other sources) and each of the associated user IDs.

From the ISPF COMMAND INPUT screen enter:
LISTUSER(each identified batch job)

The following USERID record fields/attributes must be specified:

NAME
PROTECTED

No USERID has the LAST-ACCESS field set to UNKNOWN.

If both of the above are true, this is not a finding.

If either of the USERID record fields/attributes (NAME and/or PROTECTED) are blank and/or the LAST ACCESS field is set to unknown, this is a finding.'
  desc 'fix', 'Ensure the following:

Associated USERIDs are defined for all batch jobs and documentation authorizing access to system resources is maintained and implemented.

Set up the userids with the RACF PROTECTED attribute. A sample RACF command to accomplish is shown here: ALU <execution-userid> NOPASSWORD NOOIDCARD.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25385r514824_chk'
  tag severity: 'medium'
  tag gid: 'V-223712'
  tag rid: 'SV-223712r604139_rule'
  tag stig_id: 'RACF-ES-000650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25373r514825_fix'
  tag 'documentable'
  tag legacy: ['V-98131', 'SV-107235']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

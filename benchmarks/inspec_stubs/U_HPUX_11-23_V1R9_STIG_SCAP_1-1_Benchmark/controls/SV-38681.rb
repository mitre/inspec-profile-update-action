control 'SV-38681' do
  title 'The system must be configured to operate in a security mode.'
  desc 'When operating in standard  mode, account passwords are stored in the /etc/passwd file, which is world readable. By operating in either Trusted Mode or Standard Mode with Security Extensions, the system security posture is enhanced thru the addition of a secure, non-world readable password container other than /etc/passwd.'
  desc 'fix', 'SAM/SMH must be used to convert standard mode HP-UX to Trusted Mode (optional for SMSE). 
For Trusted Mode only:
The following command may be used to “manually” convert from Standard Mode to Trusted Mode (note that its use is not vendor supported):
# tsconvert -c

For SMSE only:
The following command may be used to “manually” create the /etc/shadow file with information from the /etc/passwd file (use of this commend is vendor supported).
# pwconv

Note that additional software bundles and/or patches may be required in order to completely convert a standard mode system to SMSE.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-960'
  tag rid: 'SV-38681r2_rule'
  tag stig_id: 'GEN000000-HPUX0020'
  tag gtitle: 'GEN000000-HPUX0020'
  tag fix_id: 'F-33047r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000293', 'CCI-000633']
  tag nist: ['CM-2', 'SA-4 (6) (b)']
end

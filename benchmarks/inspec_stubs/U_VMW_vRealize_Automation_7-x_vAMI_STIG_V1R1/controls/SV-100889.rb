control 'SV-100889' do
  title 'The vAMI error logs must be reviewed.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team. Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The extent to which the application server is able to identify and handle error conditions is guided by organizational policy and operational requirements. Adequate logging levels and system performance capabilities need to be balanced with data protection requirements. The structure and content of error messages needs to be carefully considered by the organization and development team. Application servers must have the capability to log at various levels, which can provide log entries for potential security-related error events. An example is the capability for the application server to assign a criticality level to a failed logon attempt error message, a security-related error message being of a higher criticality.'
  desc 'check', 'Interview the ISSO and/or the SA and review vRA product documentation.
 
Determine a local procedure exists for monitoring error conditions reported by the vAMI.
 
If a procedure does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to monitor error conditions reported by the vAMI.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90239'
  tag rid: 'SV-100889r1_rule'
  tag stig_id: 'VRAU-VA-000340'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag fix_id: 'F-96981r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end

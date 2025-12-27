control 'SV-223470' do
  title 'IBM z/OS procedures must restrict ACF2 LOGONIDs with the READALL attribute to auditors and/or authorized users.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. A crucial part of any flow control solution is the ability to configure policy filters. This allows the operating system to enforce multiple and different security policies. Policy filters serve to enact and enforce the organizational policy as it pertains to controlling data flow.'
  desc 'check', 'From the ACF Command line enter:
SET LID
LIST IF(READALL)

If procedures are in place to ensure logonids with the READALL attribute are used and controlled in accordance with the DISA requirements, this is not a finding.

The READALL privilege is available for actual auditing of system data. It gives the capability of looking at every data set on the system despite the data set rules. Its use is strongly discouraged. Always grant access through the use of standard data set access rules. Under no circumstances will the privilege be used as a convenience to the person maintaining the rule sets. Only use this privilege when absolutely necessary, and only give it to auditors. Remove the privilege once the audit is complete. Fully document the granting and revoking of the access.'
  desc 'fix', 'Develop procedures to control Logonids with the READALL attribute.

The READALL privilege is available for actual auditing of system data. It gives the capability of looking at every data set on the system despite the data set rules. Its use is strongly discouraged. Always grant access through the use of standard data set access rules. Under no circumstances will the privilege be used as a convenience to the person maintaining the rule sets. Only use this privilege when absolutely necessary, and only give it to auditors. Remove the privilege once the audit is complete. Fully document the granting and revoking of the access.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25143r504528_chk'
  tag severity: 'medium'
  tag gid: 'V-223470'
  tag rid: 'SV-223470r533198_rule'
  tag stig_id: 'ACF2-ES-000520'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25131r504529_fix'
  tag 'documentable'
  tag legacy: ['V-97639', 'SV-106743']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

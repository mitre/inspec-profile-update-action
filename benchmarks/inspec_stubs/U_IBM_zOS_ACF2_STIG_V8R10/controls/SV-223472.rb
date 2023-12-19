control 'SV-223472' do
  title 'IBM z/OS LOGONIDs with the AUDIT or CONSULT attribute must be properly scoped.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. A crucial part of any flow control solution is the ability to configure policy filters. This allows the operating system to enforce multiple and different security policies. Policy filters serve to enact and enforce the organizational policy as it pertains to controlling data flow.'
  desc 'check', 'From the ACF Command Screen enter:
SET LID
LIST IF(AUDIT)

If all logonids with the attributes AUDIT and/or CONSULT also do not have the SCPLIST attribute specified properly according to job function and areas of responsibility, this is a finding.

NOTE: SCPLST attributes are not required for Logonids with the attributes AUDIT or CONSULT if the security ISSM/ISSO determines it requires ability to view the entire ACF2 environment. SCPLST attributes are not required for Auditors, Domain Level Security Admin Logonids, and BATCH Logonids that review the entire ACF2 environment to include GSO records, data set and resource rules, etc. or run audit reports.'
  desc 'fix', 'Configure logonids with the AUDIT or CONSULT attributes are restricted by a SCPLIST attribute that restricts authority based on job function and area of responsibility.

The following user attributes allow viewing of the ACF2 databases for the purpose of inspecting users, data set access rules, and Infostorage records. When granted to a logonid, restrict the scope of the following attributes using an associated SCPLIST (scope list) record:

AUDIT
CONSULT

NOTE: SCPLST attributes are not required for Logonids with the attributes AUDIT or CONSULT if the security ISSM/ISSO determines it requires ability to view the entire ACF2 environment. SCPLST attributes are not required for Auditors, Domain Level Security Admin Logonids, and BATCH Logonids that review the entire ACF2 environment to include GSO records, data set and resource rules, etc. or run audit reports.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25145r504534_chk'
  tag severity: 'medium'
  tag gid: 'V-223472'
  tag rid: 'SV-223472r533198_rule'
  tag stig_id: 'ACF2-ES-000540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25133r504535_fix'
  tag 'documentable'
  tag legacy: ['SV-106747', 'V-97643']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

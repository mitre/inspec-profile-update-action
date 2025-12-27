control 'SV-223471' do
  title 'IBM z/OS must have the RULEVLD and RSRCVLD attributes specified for LOGONIDs with the SECURITY attribute.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. A crucial part of any flow control solution is the ability to configure policy filters. This allows the operating system to enforce multiple and different security policies. Policy filters serve to enact and enforce the organizational policy as it pertains to controlling data flow.'
  desc 'check', 'From the ACF Command screen enter:
SET LID
LIST IF(SECURITY)

If all logonids with the SECURITY attribute also have the RULEVLD and RSRCVLD attributes specified, this not a finding.

If any logonid with the SECURITY attribute does not have the RULEVLD and/or RSRCVLD attributes specified, this is a finding.'
  desc 'fix', 'Configure Logonids with the SECURITY attribute to have the RULEVLD and RSRCVLD attributes specified.

If a logonid is granted the SECURITY privilege, it is mandatory that RULEVLD and RSRCVLD attributes will also be specified for the logonid.

Example:
SET LID
CHANGE logonid RULEVLD RSRCVLD'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25144r504531_chk'
  tag severity: 'medium'
  tag gid: 'V-223471'
  tag rid: 'SV-223471r533198_rule'
  tag stig_id: 'ACF2-ES-000530'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25132r504532_fix'
  tag 'documentable'
  tag legacy: ['V-97641', 'SV-106745']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

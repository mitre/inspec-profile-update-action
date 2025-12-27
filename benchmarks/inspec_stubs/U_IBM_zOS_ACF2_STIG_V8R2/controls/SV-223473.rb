control 'SV-223473' do
  title 'IBM z/OS LOGONID with the ACCTPRIV attribute must be restricted to the ISSO.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. A crucial part of any flow control solution is the ability to configure policy filters. This allows the operating system to enforce multiple and different security policies. Policy filters serve to enact and enforce the organizational policy as it pertains to controlling data flow.'
  desc 'check', 'From the ACF Command screen enter:
SET LID
LIST IF(ACCTPRIV)

If logonids with the ACCTPRIV attribute specified are not assigned to the security administrator, this is a finding.'
  desc 'fix', 'Configure logonids with the ACCTPRIV attribute to be only reserved for use by the Security manager.

The ACCTPRIV attribute cannot be scoped, and will be restricted exclusively to a site security administrator:

Example:
SET LID
CHANGE logonid ACCTPRIV'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25146r500551_chk'
  tag severity: 'medium'
  tag gid: 'V-223473'
  tag rid: 'SV-223473r533198_rule'
  tag stig_id: 'ACF2-ES-000550'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25134r500552_fix'
  tag 'documentable'
  tag legacy: ['SV-106749', 'V-97645']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

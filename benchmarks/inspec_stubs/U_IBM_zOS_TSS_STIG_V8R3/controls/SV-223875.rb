control 'SV-223875' do
  title 'The number of CA-TSS ACIDs possessing the tape Bypass Label Processing (BLP) privilege must be limited.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. A crucial part of any flow control solution is the ability to configure policy filters. This allows the operating system to enforce multiple and different security policies. Policy filters serve to enact and enforce the organizational policy as it pertains to controlling data flow.'
  desc 'check', 'From the ISPF Command Shell enter: 
TSS LIST(ACIDS) DATA(BASIC)

If only authorized personnel have BLP access and documentation for access is on file with the ISSO, this is not a finding.'
  desc 'fix', 'Review all ACIDs with the BLP attribute. Evaluate the impact of removing BLP access from unauthorized personnel. Develop a plan of action and remove BLP access from unauthorized ACIDs.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25548r516024_chk'
  tag severity: 'medium'
  tag gid: 'V-223875'
  tag rid: 'SV-223875r561402_rule'
  tag stig_id: 'TSS0-ES-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25536r516025_fix'
  tag 'documentable'
  tag legacy: ['SV-107561', 'V-98457']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

control 'SV-223837' do
  title 'IBM RACF LOGONIDs must not be defined to SYS1.UADS for non-emergency use.'
  desc 'Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Ask the system administrator to provide a list of all emergency userids available to the site along with the associated function of each.

 If SYS1.UADS userids are limited and reserved for emergency purposes only, this is not a finding.'
  desc 'fix', 'Configure the SYS1.UADS entries to ensure LOGONIDs defined include only those users required to support specific functions related to system recovery. Evaluate the impact of accomplishing the change.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25510r515199_chk'
  tag severity: 'high'
  tag gid: 'V-223837'
  tag rid: 'SV-223837r877392_rule'
  tag stig_id: 'RACF-TS-000020'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25498r515200_fix'
  tag 'documentable'
  tag legacy: ['V-98381', 'SV-107485']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

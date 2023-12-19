control 'SV-224073' do
  title 'CA-TSS LOGONIDs must not be defined to SYS1.UADS for non-emergency use.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Ask the system administrator to provide a list of all emergency userids available to the site along with the associated function of each.

If any SYS1.UADS userids are assigned for other than emergency purposes, this is a finding.'
  desc 'fix', 'Configure the SYS1.UADS entries to ensure LOGONIDs defined include only those users required to support specific functions related to system recovery. Evaluate the impact of accomplishing the change.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25746r516618_chk'
  tag severity: 'high'
  tag gid: 'V-224073'
  tag rid: 'SV-224073r856138_rule'
  tag stig_id: 'TSS0-TS-000020'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25734r516619_fix'
  tag 'documentable'
  tag legacy: ['SV-107957', 'V-98853']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

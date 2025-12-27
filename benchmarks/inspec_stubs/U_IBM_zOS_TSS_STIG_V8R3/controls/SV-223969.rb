control 'SV-223969' do
  title 'CA-TSS ACIDs granted the CONSOLE attribute must be justified.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Execute TSS Report TSS AUDIT with PRIVILEGES control statement PRIVILEGES [SHORT]. For more information TSSAUDIT reports refer to the CA-TSS Report and Tracking Guide. Refer to the resulting report.

If ACIDs with CONSOLE authority are limited to authorized SCA security administrators and the system programmers that maintain the CA-TSS software product only, this is not a finding.'
  desc 'fix', 'Review all ACIDs with the CONSOLE attribute. Ensure access is limited to authorized SCA security administrators only. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes. Ensure documentation providing justification for access is maintained and filed with the ISSO.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25642r516306_chk'
  tag severity: 'high'
  tag gid: 'V-223969'
  tag rid: 'SV-223969r561402_rule'
  tag stig_id: 'TSS0-ES-000960'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25630r516307_fix'
  tag 'documentable'
  tag legacy: ['SV-107749', 'V-98645']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

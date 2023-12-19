control 'SV-235747' do
  title 'Online revocation checks must be performed.'
  desc %q(If you enable this policy, Microsoft Edge will perform soft-fail, online OCSP/CRL checks. "Soft fail" means that if the revocation server can't be reached, the certificate will be considered valid.

If you disable the policy or don't configure it, Microsoft Edge won't perform online revocation checks.)
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable online OCSP/CRL checks" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "EnableOnlineRevocationChecks" is not set to "REG_DWORD = 1", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable online OCSP/CRL checks" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38966r766849_chk'
  tag severity: 'medium'
  tag gid: 'V-235747'
  tag rid: 'SV-235747r766851_rule'
  tag stig_id: 'EDGE-00-000030'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-38929r766850_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

control 'SV-221579' do
  title 'Online revocation checks must be done.'
  desc 'By setting this policy to true, the previous behavior is restored and online OCSP/CRL checks will be performed. If the policy is not set, or is set to false, then Chrome will not perform online revocation checks. Certificates are revoked when they have been compromised or are no longer valid, and this option protects users from submitting confidential data to a site that may be fraudulent or not secure.'
  desc 'check', 'Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If EnableOnlineRevocationChecks is not displayed under the Policy Name column or it is not set to true under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the EnableOnlineRevocationChecks value name does not exist or its value data is not set to 1, then this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
    Policy Name: Whether online OCSP/CRL checks are performed
    Policy State: Enabled
    Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23294r415864_chk'
  tag severity: 'medium'
  tag gid: 'V-221579'
  tag rid: 'SV-221579r615937_rule'
  tag stig_id: 'DTBC-0037'
  tag gtitle: 'SRG-APP-000605'
  tag fix_id: 'F-23283r415865_fix'
  tag 'documentable'
  tag legacy: ['SV-57623', 'V-44789']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

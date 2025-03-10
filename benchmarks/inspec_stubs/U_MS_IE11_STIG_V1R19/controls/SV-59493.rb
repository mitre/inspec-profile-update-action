control 'SV-59493' do
  title 'Checking for server certificate revocation must be enforced.'
  desc "This policy setting allows you to manage whether Internet Explorer will check revocation status of servers' certificates. Certificates are revoked when they have been compromised or are no longer valid, and this option protects users from submitting confidential data to a site that may be fraudulent or not secure. If you enable this policy setting, Internet Explorer will check to see if server certificates have been revoked. If you disable this policy setting, Internet Explorer will not check server certificates to see if they have been revoked. If you do not configure this policy setting, Internet Explorer will not check server certificates to see if they have been revoked."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Check for server certificate revocation' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "CertificateRevocation" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Check for server certificate revocation' to 'Enabled'."
  impact 0.3
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49795r2_chk'
  tag severity: 'low'
  tag gid: 'V-46629'
  tag rid: 'SV-59493r2_rule'
  tag stig_id: 'DTBI365-IE11'
  tag gtitle: 'DTBI365-IE11-Check for server certificate revocation'
  tag fix_id: 'F-50399r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

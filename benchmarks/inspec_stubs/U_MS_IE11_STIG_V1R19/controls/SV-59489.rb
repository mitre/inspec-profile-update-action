control 'SV-59489' do
  title 'Software must be disallowed to run or install with invalid signatures.'
  desc "Microsoft ActiveX controls and file downloads often have digital signatures attached that certify the file's integrity and the identity of the signer (creator) of the software. Such signatures help ensure unmodified software is downloaded and the user can positively identify the signer to determine whether you trust them enough to run their software."
  desc 'check', %q(Note: Some legitimate software and controls may have an invalid signature. You should carefully test such software in isolation before it is allowed to be used on an organization's network.

The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Allow software to run or install even if the signature is invalid' must be 'Disabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Download Criteria: If the value "RunInvalidSignatures" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page -> 'Allow software to run or install even if the signature is invalid' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49791r3_chk'
  tag severity: 'medium'
  tag gid: 'V-46625'
  tag rid: 'SV-59489r2_rule'
  tag stig_id: 'DTBI350-IE11'
  tag gtitle: 'DTBI350-IE11-Software with invalid signatures'
  tag fix_id: 'F-50395r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end

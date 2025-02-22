control 'SV-235722' do
  title 'The list of domains for which Microsoft Defender SmartScreen will not trigger warnings must be whitelisted if used.'
  desc 'Configure the list of Microsoft Defender SmartScreen trusted domains. This means Microsoft Defender SmartScreen will not check for potentially malicious resources, such as phishing software and other malware, if the source URLs match these domains. The Microsoft Defender SmartScreen download protection service will not check downloads hosted on these domains.

If this policy is enabled, Microsoft Defender SmartScreen trusts these domains. If the policy is disabled or not set, default Microsoft Defender SmartScreen protection is applied to all resources.'
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Configure the list of domains for which Microsoft Defender SmartScreen won't trigger warnings" may be set to "allow" for whitelisted domains.

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge

SmartScreenAllowListDomains may be set as follows:
HKLM\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains\1 = mydomain.com
HKLM\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains\2 = myagency.mil

This requirement for "SmartScreenAllowListDomains" is not required; this is optional.

If configured, the list of domains for which Microsoft Defender SmartScreen will not trigger warnings must be whitelisted; otherwise this is a finding.

If this machine is on SIPRNet, this is Not Applicable.)
  desc 'fix', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Configure the list of domains for which Microsoft Defender SmartScreen won't trigger warnings" may be set to "allow" for whitelisted domains.)
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38941r626362_chk'
  tag severity: 'low'
  tag gid: 'V-235722'
  tag rid: 'SV-235722r626523_rule'
  tag stig_id: 'EDGE-00-000004'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-38904r626363_fix'
  tag 'documentable'
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end

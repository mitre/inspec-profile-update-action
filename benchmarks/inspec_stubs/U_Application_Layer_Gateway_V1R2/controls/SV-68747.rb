control 'SV-68747' do
  title 'The ALG must be configured to remove or disable unrelated or unneeded application proxy services.'
  desc 'Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of the ALG. Multiple application proxies can be installed on many ALGs. However, proxy types must be limited to related functions. At a minimum, the web and email gateway represent different security domains/trust levels. Organizations should also consider separation of gateways that service the DMZ and the trusted network.'
  desc 'check', 'Review the ALG configuration to determine if application proxies are installed which are not related to the purpose of the gateway.

If the ALG has unrelated or unneeded application proxy services installed, this is a finding.'
  desc 'fix', 'Remove application proxy services that are unrelated or unneeded to the primary function of the ALG.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55117r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54501'
  tag rid: 'SV-68747r1_rule'
  tag stig_id: 'SRG-NET-000131-ALG-000086'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-59355r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

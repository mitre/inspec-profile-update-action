control 'SV-68935' do
  title 'The ALG that implements spam protection mechanisms must be updated automatically.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat.

A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functionality.'
  desc 'check', 'If the ALG does not provide spam protection functions, this is not applicable.

Verify the ALG automatically updates spam protection mechanisms.

If the ALG does not automatically update spam protection mechanisms, this is a finding.'
  desc 'fix', 'If the ALG provides spam protection functions, configure the ALG to automatically update spam protection mechanisms.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54689'
  tag rid: 'SV-68935r1_rule'
  tag stig_id: 'SRG-NET-000393-ALG-000144'
  tag gtitle: 'SRG-NET-000393-ALG-000144'
  tag fix_id: 'F-59545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end

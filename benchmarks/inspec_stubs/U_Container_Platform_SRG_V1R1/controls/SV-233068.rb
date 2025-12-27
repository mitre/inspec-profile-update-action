control 'SV-233068' do
  title 'The container platform must limit privileges to the container platform keystore.'
  desc 'The container platform keystore is used to store credentials used to build a trust between the container platform and some external source. This trust relationship is authorized by the organization. If a malicious user were to have access to the container platform keystore, two negative scenarios could develop:

1) Keys not approved could be introduced and 
2) Approved keys deleted, leading to the introduction of container images from sources that were never approved by the organization. 

To thwart this threat, it is important to protect the container platform keystore and give access to only those individuals and roles approved by the organization.'
  desc 'check', 'Review the container platform keystore configuration to determine if the level of access to the keystore is controlled through user privileges. 

Attempt to perform keystore operations to determine if the privileges are enforced. 

If the container platform keystore is not limited through user privileges or the user privileges are not enforced, this is a finding.'
  desc 'fix', 'Configure the container platform to use and enforce user privileges when accessing the container platform keystore.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36004r599716_chk'
  tag severity: 'medium'
  tag gid: 'V-233068'
  tag rid: 'SV-233068r599716_rule'
  tag stig_id: 'SRG-APP-000133-CTR-000300'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-35972r598841_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

control 'SV-6778' do
  title 'Communications from the management console to the SAN fabric are not protected strong two-factor authentication.'
  desc 'Using two-factor authentication between the SAN management console and the fabric enhances the security of the communications carrying privileged functions.  It is harder for an unauthorized management console to take control of the SAN.

The preferred solution for two-factor authentication is DoD PKI implemented on the CAC or Alternative (Alt) token.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that communications from the management console to the SAN fabric are protected using DOD PKI.  If another method of two-factor authentication is used, then inspect approval documentation. 

If two-factor authentication is not used, this is a finding.

If two-factor authentication method is not DoD PKI and no approval documentation exists, this is a finding.'
  desc 'fix', 'Develop a plan to migrate to the use of DoD PKI authentication between the SAN management console and the SAN fabric.  Obtain CM approval of the plan and implement the plan.'
  impact 0.3
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2544r1_chk'
  tag severity: 'low'
  tag gid: 'V-6637'
  tag rid: 'SV-6778r1_rule'
  tag stig_id: 'SAN04.014.00'
  tag gtitle: 'Management Console to SAN Fabric Authentication'
  tag fix_id: 'F-6235r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end

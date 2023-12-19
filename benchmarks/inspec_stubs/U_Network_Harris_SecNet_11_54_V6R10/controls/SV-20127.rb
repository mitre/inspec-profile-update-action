control 'SV-20127' do
  title 'Before a Secure WLAN (SWLAN) becomes operational and is connected to the SIPRNet the Certified TEMPEST Technical Authority (CTTA) must be notified.'
  desc 'Wireless signals are extremely vulnerable to both detection and interception, which can provide an adversary with the location and intensity of particular DoD activities and potentially reveal classified DoD information.  TEMPEST reviews provide assurance that unacceptable risks have been identified and mitigated.'
  desc 'check', 'Review documentation. Verify the local CTTA has been notified of the site’s intent to install and operate a SWLAN. Mark as a finding if the local CTTA has not been notified.'
  desc 'fix', 'Notify the CTTA of the need to review the SWLAN.'
  impact 0.5
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-22006r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18583'
  tag rid: 'SV-20127r1_rule'
  tag stig_id: 'WIR0220'
  tag gtitle: 'SWLAN CTTA review'
  tag fix_id: 'F-34119r1_fix'
  tag 'documentable'
  tag responsibility: ['Designated Approving Authority', 'Information Assurance Officer']
end

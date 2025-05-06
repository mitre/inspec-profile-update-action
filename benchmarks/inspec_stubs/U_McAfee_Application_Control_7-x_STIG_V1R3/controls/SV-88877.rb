control 'SV-88877' do
  title 'The configuration of features under McAfee Application Control Options policies Enforce feature control must be documented in the organizations written policy.'
  desc 'By default, the McAfee Application Control prevents installation of ActiveX controls on endpoints, enforces memory protection techniques on endpoints, and prevents MSI-installers from running on endpoints. The Feature Control allows for those safeguards to be bypassed and in doing so renders the McAfee Application Control less effective.'
  desc 'check', %q(Consult with the ISSO/ISSM to obtain a copy of the organization's documented policy for application whitelisting.

Review the written policy for how the Solidcore client interface is used by the organization.

Verify the written policy identifies whether additional features are enabled or not under "Enforce feature control" of the McAfee Application Control Options ePO policy.

If the written policy does not identify whether additional features are enabled or not under "Enforce feature control" of the McAfee Application Control Options ePO policy, this is a finding.)
  desc 'fix', 'Follow the formal change and acceptance process to document any features needing to be enabled.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74203'
  tag rid: 'SV-88877r1_rule'
  tag stig_id: 'MCAC-PO-000108'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

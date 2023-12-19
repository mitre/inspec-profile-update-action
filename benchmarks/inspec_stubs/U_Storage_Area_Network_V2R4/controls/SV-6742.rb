control 'SV-6742' do
  title 'Servers and other hosts are not compliant with applicable Operating System (OS) STIG requirements.'
  desc 'SAN servers and other hosts are hardware software combinations that actually run under the control of a native OS found on the component.  This OS may be UNIX, LNIX, Windows, etc.  The underlying OS must be configured to be compliant with the applicable STIG to ensure that they do not insert known vulnerabilities into the DOD network infrastructure.
The IAO/NSO will ensure that servers and other hosts are compliant with applicable Operating System (OS) STIG requirements.'
  desc 'check', 'The reviewer will interview the IAO/NSO and view the VMS to verify that servers and other hosts are compliant with applicable Operating System (OS) STIG requirements.'
  desc 'fix', 'Perform a self assessment using the applicable OS checklists or scripts on any server or host in the SAN that has not been reviewer or request a formal review from FSO.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2469r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6622'
  tag rid: 'SV-6742r1_rule'
  tag stig_id: 'SAN04.005.00'
  tag gtitle: 'Servers and hosts OS STIG Requirements'
  tag fix_id: 'F-6211r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Some SAN software may not function correctly on a STIG compliant server or host.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'DCCS-1, DCCS-2'
end

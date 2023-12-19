control 'SV-55744' do
  title 'An IP-based VTC system implementing a single CODEC supporting conferences on multiple networks having different classification levels (i.e., unclassified, SECRET, TOP SECRET, TS-SCI) must support Periods Processing by being sanitized of all information while transitioning from one period/network to the next.'
  desc 'All residual data (data that is unintentionally left behind on computer media) must be cleared before transitioning from one period/network to the next. Since the equipment is reused, non-destructive techniques are used.
According to NIST Special Publication 800-88:
Clearing information is a level of media sanitization that would protect the confidentiality of information against a robust keyboard attack. Simple deletion of items would not suffice for clearing. Clearing must not allow information to be retrieved by data, disk, or file recovery utilities. It must be resistant to keystroke recovery attempts executed from standard input devices and from data scavenging tools. For example, overwriting is an acceptable method for clearing media.'
  desc 'check', 'Verify that an automatic capability exists and review documentation to determine whether this capability is being implemented before transitioning from one period/network to the next. If no automatic capability exists, review organizational documentation to determine whether a manual procedure is specified and implemented before transitioning from one period/network to the next. Coordinate with the vendor/solutions provider and certifier to ensure all residual information is sanitized based on equipment make and model.

If an automatic capability exists and is being implemented, this is not a finding.
If an automatic capability exists but is not being implemented, this is a finding unless a manual procedure is specified and is being implemented.
If a manual procedure is specified and is being implemented, this is not a finding.
If no procedure is specified or none being implemented, this is a finding.'
  desc 'fix', 'Obtain equipment that has an automatic capability to sanitize memory or implement and document a manual procedure.  Implement the automatic capability or manual procedure to sanitize all information while transitioning from one period/network to the next.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49172r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43015'
  tag rid: 'SV-55744r1_rule'
  tag stig_id: 'RTS-VTC 7000'
  tag gtitle: 'RTS-VTC 7000 [IP]'
  tag fix_id: 'F-48599r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCCS-2, ECSC-1'
end

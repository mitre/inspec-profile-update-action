control 'SV-77555' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must be configured to receive all patches, service packs and updates from a DoD-managed source.'
  desc 'Anti-virus signature files are updated almost daily by anti-virus software vendors. These files are made available to anti-virus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The anti-virus software product must be configured to receive those updates automatically in order to afford the expected protection.

While obtaining updates, patches, service packs and updates from the vendor are timelier, the possibility of corruption or malware being introduced to the system is higher. By obtaining these from an official DoD source and/or downloading them to a separate system first and validating them before making them available to systems, the possibility of malware being introduced is mitigated.'
  desc 'check', 'Log into the ePO server console.

From Menu, select Configuration >> Server Settings.

From Setting Categories, select Source Sites.

Verify the DoD-controlled entry (mcafee.csd.disa.mil) for source repositories is present.

If the DoD-controlled entry for source sites is not present, this is a finding.

Note: If this is a disconnected network, this requirement can be met via the use of a manual distribution. The process must be documented and meet the requirements for frequency as defined in this document.

Note: If the ePO server is outside of the .mil address space (such as, .edu, .gov, etc.), connection to the DoD-controlled servers for updates will not be possible. In this case, updates from the vendor are acceptable and this check should be marked NA.'
  desc 'fix', 'Configure the ePO server to use the DoD-controlled source repository.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63065'
  tag rid: 'SV-77555r1_rule'
  tag stig_id: 'DTAVSEL-201'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-68983r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

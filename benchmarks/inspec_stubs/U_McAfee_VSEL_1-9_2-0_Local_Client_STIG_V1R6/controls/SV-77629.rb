control 'SV-77629' do
  title 'The McAfee VirusScan Enterprise must be configured to receive all patches, service packs and updates from a DoD-managed source.'
  desc 'Anti-virus signature files are updated almost daily by anti-virus software vendors. These files are made available to anti-virus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The anti-virus software product must be configured to receive those updates automatically in order to afford the expected protection.

While obtaining updates, patches, service packs and updates from the vendor are timelier, the possibility of corruption or malware being introduced to the system is higher. By obtaining these from an official DoD source and/or downloading them to a separate system first and validating them before making them available to systems, the possibility of malware being introduced is mitigated.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "Repositories".
Under "Repository List", verify all repositories listed point to a local or DoD-managed repository.

If all repositories listed do not point to local or DoD-managed repository, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", select "Repositories".

Under "Repository List", configure all repositories to point to a local or DoD-managed repository, and click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63139'
  tag rid: 'SV-77629r1_rule'
  tag stig_id: 'DTAVSEL-201'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-69057r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

control 'SV-257240' do
  title 'The macOS system must enable System Integrity Protection.'
  desc 'System Integrity Protection (SIP) is vital to the protection of the integrity of macOS. SIP restricts what actions can be performed by administrative users, including root, against protected parts of the operating system. SIP protects all system binaries, including audit tools, from unauthorized access by preventing the modification or deletion of system binaries, or the changing of the permissions associated with those binaries. SIP limits the privileges to change software resident within software libraries to processes that have signed by Apple and have special entitlements to write to system files, such as Apple software updates and Apple installers. By protecting audit binaries, SIP ensures the presence of an audit record generation capability for DOD-defined auditable events for all operating system components and supports on-demand and after-the-fact reporting requirements.

The XProtect program is part of the SIP component and is integral to protecting the operating system from malware and malicious code.

'
  desc 'check', 'Verify the macOS system is configured to enable System Integrity Protection with the following command:

/usr/bin/csrutil status

System Integrity Protection status: enabled.

If the "System Integrity Protection" is not set to "enabled", this is a finding.'
  desc 'fix', 'Configure the macOS system to enable "System Integrity Protection" by booting into "Recovery" mode, then launch "Terminal" from the "Utilities" menu, and run the following command:

/usr/bin/csrutil enable'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60925r905351_chk'
  tag severity: 'high'
  tag gid: 'V-257240'
  tag rid: 'SV-257240r905353_rule'
  tag stig_id: 'APPL-13-005001'
  tag gtitle: 'SRG-OS-000051-GPOS-00024'
  tag fix_id: 'F-60866r905352_fix'
  tag satisfies: ['SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142']
  tag 'documentable'
  tag cci: ['CCI-000154', 'CCI-000158', 'CCI-000169', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001499', 'CCI-001875', 'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882']
  tag nist: ['AU-6 (4)', 'AU-7 (1)', 'AU-12 a', 'AU-9 a', 'AU-9', 'AU-9', 'CM-5 (6)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 b', 'AU-7 b']
end

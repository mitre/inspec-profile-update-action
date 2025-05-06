control 'SV-226954' do
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc 'The -l option allows basic logging of connections.  The verbose (on HP) and the debug (on Solaris) allow logging of what files the FTP session transferred.  This extra logging makes it possible to easily track which files are being transferred onto or from a system.  If they are not configured, the only option for tracking is the audit files.  The audit files are much harder to read.  If auditing is not properly configured, then there would be no record at all of the file transfer transactions.'
  desc 'check', 'Verify the FTP daemon is invoked with the -l option by SMF.
# inetadm -l ftp | grep in.ftpd
If the exec name-value pair does not include the -l option for in.ftpd, this is a finding.'
  desc 'fix', 'Add the -l option to the exec name-value pair used by SMF to invoke the FTP daemon.
# inetadm -m ftp exec="/usr/sbin/in.ftpd [other options] -l"
Refresh inetd.
# svcadm refresh inetd'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29116r485189_chk'
  tag severity: 'low'
  tag gid: 'V-226954'
  tag rid: 'SV-226954r603265_rule'
  tag stig_id: 'GEN004980'
  tag gtitle: 'SRG-OS-000037'
  tag fix_id: 'F-29104r485190_fix'
  tag 'documentable'
  tag legacy: ['V-845', 'SV-40816']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

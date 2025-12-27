control 'SV-226958' do
  title 'The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.'
  desc 'Secure mode limits TFTP requests to a specific directory.  If TFTP is not running in secure mode, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', 'Determine if TFTPD is running in secure mode.

# grep tftp /etc/inet/inetd.conf
OR
# svccfg -s tftp/udp6 listprop |grep in.tftpd |grep exec

If any returned service line does not use the -s parameter to TFTPD, this is a finding. If TFTP is not installed this check is not applicable.'
  desc 'fix', 'Edit /etc/inet/inetd.conf and add the -s parameter to TFTPD.
# inetconv

OR

Update the SMF entry for the TFTP daemon.
# svccfg -s tftp/udp6 setprop inetd_start/exec = "astring:\\"/usr/sbin/in.tftpd -s <other TFTPD options>\\""'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29120r485201_chk'
  tag severity: 'high'
  tag gid: 'V-226958'
  tag rid: 'SV-226958r603265_rule'
  tag stig_id: 'GEN005080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29108r485202_fix'
  tag 'documentable'
  tag legacy: ['SV-28419', 'V-847']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

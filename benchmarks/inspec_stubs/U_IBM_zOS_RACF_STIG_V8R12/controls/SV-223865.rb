control 'SV-223865' do
  title 'IBM z/OS HFS objects for the z/OS UNIX Telnet Server must be properly protected.'
  desc 'HFS directories and files of the z/OS UNIX Telnet Server provide the configuration and executable properties of this product. Failure to properly secure these objects may lead to unauthorized access resulting in the compromise of the integrity and availability of the operating system environment, ACP, and customer data.

'
  desc 'check', 'From the ISPF Command Shell enter:
omvs
At the input line enter
cd /usr
enter
ls -alW

If the following File permission and user Audit Bits are true, this is not a finding.

/usr/sbin/otelnetd 1740 fff

cd /etc
ls -alW

If the following file permission and user Audit Bits are true, this is not a finding.

/etc/banner 0744 faf

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:

f log for failed access attempts
a log for failed and successful access
- no auditing'
  desc 'fix', 'With the assistance of a systems programmer with UID(0) and/or SUPERUSER access, will review the UNIX permission bits and user audit bits on the HFS directories and files for the z/OS UNIX Telnet Server. Ensure they conform to the specifications below:

z/OS UNIX TELNET Server HFS Object Security Settings
File Permission Bits User Audit Bits
/usr/sbin/otelnetd 1740 fff
/etc/banner 0744 faf

NOTE:
The /usr/sbin/otelnetd object is a symbolic link to /usr/lpp/tcpip/sbin/otelnetd. The permission and user audit bits on the target of the symbolic link must have the required settings.

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:

f log for failed access attempts
a log for failed and successful access
- no auditing

The following commands can be used (from a user account with an effective UID(0)) to update the permission bits and audit bits:

chmod 1740 /usr/lpp/tcpip/sbin/otelnetd
chaudit rwx=f /usr/lpp/tcpip/sbin/otelnetd
chmod 0744 /etc/banner
chaudit w=sf,rx+f /etc/banner'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25538r515283_chk'
  tag severity: 'medium'
  tag gid: 'V-223865'
  tag rid: 'SV-223865r604139_rule'
  tag stig_id: 'RACF-UT-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25526r515284_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-98437', 'SV-107541']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end

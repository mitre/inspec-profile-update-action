control 'SV-223822' do
  title 'IBM z/OS permission bits and user audit bits for HFS objects that are part of the Base TCP/IP component must be properly configured.'
  desc 'HFS directories and files of the Base TCP/IP component provide the configuration, operational, and executable properties of IBMs TCP/IP system product. Failure to properly secure these objects may lead to unauthorized access resulting in the compromise of the integrity and availability of the operating system environment, ACP, and customer data.'
  desc 'check', 'From the ISPF Command Shell enter:
omvs

At the input line enter:
cd /etc
enter
ls -alW

If the following file permission and user Audit Bits are true, this is not a finding.

/etc/hosts 0744 faf
/etc/protocol 0744 faf
/etc/resolv.conf 0744 faf
/etc/services 0740 faf

cd /usr
ls -alW

If the following file permission and user Audit Bits are true, this is not a finding.

/usr/lpp/tcpip/sbin 0755 faf
/usr/lpp/tcpip/bin 0755 faf

Notes: Some of the files listed above are not used in every configuration. The absence of a file is not considered a finding.

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
  desc 'fix', 'With the assistance of a systems programmer with UID(0) and/or SUPERUSER access, configure the UNIX permission bits and user audit bits on the HFS directories and files for the FTP Server to conform to the specifications in the table below:

BASE TCP/IP HFS Object Security Settings
File Permission Bits User Audit Bits
/etc/hosts 0744 faf
/etc/protocol 0744 faf
/etc/resolv.conf 0744 faf
/etc/services 0740 faf
/usr/lpp/tcpip/sbin 0755 faf
/usr/lpp/tcpip/bin 0755 faf

Some of the files listed above (e.g., /etc/resolv.conf) are not used in every configuration. While the absence of a file is generally not a security issue, the existence of a file that has not been properly secured can often be an issue. Therefore, all directories and files that do exist will have the specified permission and audit bit settings.

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

chmod 0744 /etc/hosts
chaudit w=sf,rx+f /etc/hosts
chmod 0744 /etc/protocol
chaudit w=sf,rx+f /etc/protocol
chmod 0744 /etc/resolv.conf
chaudit w=sf,rx+f /etc/resolv.conf
chmod 0740 /etc/services
chaudit w=sf,rx+f /etc/services
chmod 0755 /usr/lpp/tcpip/bin
chaudit w=sf,rx+f /usr/lpp/tcpip/bin
chmod 0755 /usr/lpp/tcpip/sbin
chaudit w=sf,rx+f /usr/lpp/tcpip/sbin'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25495r515154_chk'
  tag severity: 'medium'
  tag gid: 'V-223822'
  tag rid: 'SV-223822r604139_rule'
  tag stig_id: 'RACF-TC-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25483r515155_fix'
  tag 'documentable'
  tag legacy: ['V-98351', 'SV-107455']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

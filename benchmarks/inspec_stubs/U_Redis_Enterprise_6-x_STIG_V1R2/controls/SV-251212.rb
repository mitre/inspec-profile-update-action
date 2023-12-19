control 'SV-251212' do
  title 'Database software, including DBMS configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'The default directories that Redis Enterprise Software uses for data and metadata are:

1. /var/opt/redislabs - Default storage location for the cluster data, system logs, backups and ephemeral, persisted data
2. /var/opt/redislabs/log - System logs for Redis Enterprise Software
3. /var/opt/redislabs/run - Socket files for Redis Enterprise Software
4. /etc/opt/redislabs - Default location for cluster manager configuration and certificates
5. /tmp - Temporary files
6.  /opt/redislabs - Main installation directory for all Redis Enterprise Software binaries
7. /opt/redislabs/bin - Binaries for all the utilities for command line access and managements such as "rladmin" or "redis-cli"
8. /opt/redislabs/config - System configuration files
9. /opt/redislabs/lib - System library files
10. /opt/redislabs/sbin - System binaries for tweaking provisioning

To check this finding, examine the documentation for third-party applications and verify that no other applications are installed in these directories. It is recommended that Redis Enterprise be installed on a single tenant operating system.

If another application is using these directories on the host operating system, this is a finding.'
  desc 'fix', 'To resolve this issue, perform one of the two following actions:
1. Install Redis Enterprise on a single tenant operating system.
2. Uninstall third-party applications that have been installed in the Redis Enterprise directories and install them in separate directories.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54647r804824_chk'
  tag severity: 'medium'
  tag gid: 'V-251212'
  tag rid: 'SV-251212r804826_rule'
  tag stig_id: 'RD6X-00-007500'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-54601r804825_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

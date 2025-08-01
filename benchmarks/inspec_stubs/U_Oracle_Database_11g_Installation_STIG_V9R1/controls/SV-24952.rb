control 'SV-24952' do
  title 'The Oracle listener.ora file should specify IP addresses rather than host names to identify hosts.'
  desc 'The use of IP address in place of host names helps to protect against malicious corruption or spoofing of host names. Use of static IP addresses is considered more stable and reliable than use of hostnames or Fully Qualified Domain Names (FQDN).'
  desc 'check', 'If a listener is not running on the local database host server, this check is Not a Finding.

Review all listener.ora files for the HOST =.

Verify the HOST = value specifies an IP address for all occurrences of the HOST = setting.

Sample:

(ADDRESS= (PROTOCOL=TCP) (HOST= [host IP address]) (PORT=1521))

If any addresses specify a host name in place of an IP or other network address, this is a Finding.

NOTE: If a host name is used, ensure it can be locally resolved to an IP address on the DBMS system using a host table, however, if a hostname is used, it is still a Finding.'
  desc 'fix', 'Edit the listener.ora file and replace any HOST= [hostname or domain name] to use static IP addresses for the host.

The listener.ora file is by default located in the ORACLE_HOME/network/admin directory or the directory specified in the TNS_ADMIN environment variable for the listener service or process owner account.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29491r1_chk'
  tag severity: 'low'
  tag gid: 'V-16031'
  tag rid: 'SV-24952r1_rule'
  tag stig_id: 'DO6746-ORACLE11'
  tag gtitle: 'Oracle Listener host references'
  tag fix_id: 'F-26559r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end

control 'SV-213628' do
  title 'The EDB Postgres Advanced Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.

A database cluster listens on a single port (usually 5444 for Postgres Plus Advanced Server). The Postgres Enterprise Manager (PEM) agents do not listen on ports, they only act as clients to the PEM server. The PEM server has two components (a repository which is a Postgres database) and a PHP application. The PHP application listens on a port configured in Apache, generally 8080 or 8443.

The ports to check are: 1) The primary Postgres cluster port, 2) The PEM PHP port, and 3) The PEM Repository DB port. Generally 2 and 3 should be installed on an isolated management machine without access from anyone other than administrators.'
  desc 'check', 'Review the network functions, ports, protocols, and services supported by the DBMS.

If any protocol is prohibited by the PPSM guidance and is enabled, this is a finding.

Open "<postgresql data directory>/pg_hba.conf" in a viewer.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)  If any rows have a TYPE that is "host" or "hostnossl", this is a finding.

Execute the following SQL as enterprisedb:

SHOW port;
 
If the displayed port is not allowed, this is a finding.'
  desc 'fix', 'Disable each prohibited network function, port, protocol, or service prohibited by the PPSM guidance.

Open "<postgresql data directory>/pg_hba.conf" in an editor.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)  Change the TYPE of any rows not starting with a "#" to be either "local" or "hostssl".  The METHOD for the local rows should be "peer", which will authenticate based on the operating system name.  The METHOD for the hostssl rows should be one of these (in preferred order):   cert, ldap, sspi, pam, md5

Execute the following SQL as enterprisedb:

ALTER SYSTEM SET port = <port>;

Execute the following operating system command as root:

systemctl restart ppas-9.5.service'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14850r290196_chk'
  tag severity: 'medium'
  tag gid: 'V-213628'
  tag rid: 'SV-213628r508024_rule'
  tag stig_id: 'PPS9-00-008700'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-14848r290197_fix'
  tag 'documentable'
  tag legacy: ['V-69009', 'SV-83613']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

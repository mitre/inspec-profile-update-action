control 'SV-253734' do
  title 'MariaDB must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', "Check the ports in use by running the following command as the administrator user:

MariaDB > SHOW GLOBAL VARIABLES LIKE 'port';

If the currently defined port configuration is deemed prohibited, this is a finding."
  desc 'fix', 'To verify that mariadb system denies specific network functions, locate cnf file and specifically bind ip address to deny (or port):
        $ ls -la /etc | grep my.cnf
-rw-r--r--.   1 root root      301 Aug 25 12:45 my.cnf
      bind-address = 127.0.0.1 #just an example
   
To specifically change default port (3306) is something different:  port = 1234
bind = 10.10.10.10      #as an example 

After making changes to the .cnf file, stop and restart the database service.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57186r841725_chk'
  tag severity: 'medium'
  tag gid: 'V-253734'
  tag rid: 'SV-253734r841727_rule'
  tag stig_id: 'MADB-10-008100'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-57137r841726_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

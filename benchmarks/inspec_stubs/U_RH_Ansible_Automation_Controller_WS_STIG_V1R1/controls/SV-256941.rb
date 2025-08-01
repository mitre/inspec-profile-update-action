control 'SV-256941' do
  title "The Automation Controller servers must use encrypted communication for all channels given the high impact of those services to an organization's infrastructure."
  desc 'The Automation Controller communicates information about configuration of other information systems through its web interface and API, storing records about this information in a database. Although large portions are sanitized of sensitive information, due to the nature of this kind of information, it must always be maximally protected. Leaked details of configuration for DOD enterprise information systems could lead to compromise, so all access to and from the Automation Controller servers must be encrypted.'
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server, a TLS Configuration Check validates the TLS version used by the server:

NGINXCONF="nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}'"
sudo grep ssl_protocols ${NGINXCONF} | grep 'ssl_protocols TLSv1.2;' || echo "FAILED"

If "FAILED" is displayed, this is a finding.

A TLS Configuration Check validates the ciphers used for the web server are provided by the underlying host operating system:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
sudo grep ssl_ciphers ${NGINXCONF} | grep -q '^  *ssl_ciphers PROFILE=SYSTEM;' || echo "FAILED"

If "FAILED" is displayed, this is a finding.

A Database TLS Configuration Check validates connections to required resources use TLS connections.

Automation Controller may be configured to connect to PostgreSQL databases with or without TLS. The Administrator must check the contents of the file at /etc/tower/conf.d/postgres.py with root permissions to determine if pg_sslmode was configured with "verify-full" for any external databases at the time of installation.

Execute the following command to test the client-side database configuration:

sudo python3 -c 'exec(open("/etc/tower/conf.d/postgres.py").read()); [print(DATABASES[db]["OPTIONS"]["sslmode"]) for db in DATABASES if DATABASES[db]["HOST"] not in ("127.0.0.1", "localhost")]' | grep 'verify-full' || echo "FAILED"

If "FAILED" is displayed, this is a finding.

Execute the following commands to test the server-side database configuration:

PGCON=`sudo python3 -c 'exec(open("/etc/tower/conf.d/postgres.py").read());print(":".join((DATABASES["default"]["HOST"],DATABASES["default"]["PORT"])))'`
psql "postgresql://${PGCON}/postgres?sslmode=require" 2>/dev/null || echo FAILED

If "FAILED" is displayed, this is a finding.)
  desc 'fix', %q(As a System Administrator for each Automation Controller Web Server, reconfigure the TLS versions or ciphers used in Automation Controller's web server:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
sudo -e ${NGINXCONF}

Replace the line beginning with "ssl_protocols" to match (note the leading spaces):
"        ssl_protocols TLSv1.2;"

If the "ssl_protocols" variable does not exist, add the line after the line beginning with "ssl_ciphers".

Replace the line beginning with "ssl_ciphers" to match (note the leading spaces):
"        ssl_ciphers PROFILE=SYSTEM;"

Save the file and exit the text editor. To apply these changes to the running service immediately, restart the NGINX service with the following command:

sudo systemctl restart nginx

Database TLS Configuration Fix:

Locate the inventory file used to install Ansible Automation Platform and edit it, ensuring that the following variables are set:

pg_sslmode='verify-full'
postgres_use_ssl=true

Run the setup.sh command in the installer bundle directory to reconfigure the controller to use the new setting:

sudo ./setup.sh)
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60616r903517_chk'
  tag severity: 'medium'
  tag gid: 'V-256941'
  tag rid: 'SV-256941r903518_rule'
  tag stig_id: 'APWS-AT-000030'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-60558r903518_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

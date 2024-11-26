control 'SV-256956' do
  title "The Automation Controller NGINX web server document directory must be in a separate partition from the web server's system files."
  desc 'It is important that Automation Controller NGINX web server restricts the ability of clients to launch denial-of-service (DoS) attacks against other information systems or networks by disallowing access to system files via document and system file partitioning. DoS attacks are an attempt to negatively affect the availability of the server to end users through directory traversal and URL manipulation. An attack could compromise the end user’s access to websites and applications, which could be critical.

If a client is allowed to enable a DoS attack through access to system files, it means that the whole server or network could be shut down. In a best-case scenario, it could deny the user access to required websites and applications, which poses a threat to productivity as well as the need to spend time researching and resolving the attack. This is why it is important that Automation Controller NGINX web server does not allow access to any system files.'
  desc 'check', %q(Automation Controller serves static public content from the directory /var/lib/awx/public.

As a System Administrator for each Automation Controller NGINX web server host, verify that a separate file system/partition has been created for /var/lib/awx/public:

[[ $(sudo awk '$0~"/var/lib/awx/public" {print $2}' /etc/fstab) == "/var/lib/awx/public" ]] || echo "FAILED"

If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server host, migrate the "/var/lib/awx/public" path onto a separate file system. No automated fix is available for this action.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60631r903529_chk'
  tag severity: 'medium'
  tag gid: 'V-256956'
  tag rid: 'SV-256956r903529_rule'
  tag stig_id: 'APWS-AT-000590'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag fix_id: 'F-60573r902381_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end

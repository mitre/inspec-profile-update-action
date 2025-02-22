control 'SV-256944' do
  title 'All Automation Controller NGINX front-end web server files must be verified for their integrity (e.g., checksums and hashes) before becoming part of the production web server.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and nonrepudiation of the information. 

The Automation Controller NGINX web server host must have a mechanism to verify that files are valid prior to installation.'
  desc 'check', 'As a System Administrator, for each Automation Controller NGINX web server host, verify the integrity of the Automation Controller NGINX web server hosts files:

aide --check

Verify the displayed checksums against previously reserved checksums of the Advanced Intrusion Detection Environment (AIDE) database.

If there are any unauthorized or unexplained changes against previous checksums, this is a finding.'
  desc 'fix', 'As a System Administrator, for each Automation Controller NGINX web server host, check for existing or install AIDE:

yum install -y aide

Create or update the AIDE database immediately after initial installation of each Automation Controller NGINX web server host:

aide --init && mv /var/lib/aide/aide.db.new.gz  /var/lib/aide/aide.db.gz

Accept any expected changes to the host by updating the AIDE database:

aide --update

The output will provide checksums for the AIDE database. Save in a protected location.'
  impact 0.7
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60619r902344_chk'
  tag severity: 'high'
  tag gid: 'V-256944'
  tag rid: 'SV-256944r902346_rule'
  tag stig_id: 'APWS-AT-000230'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-60561r902345_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

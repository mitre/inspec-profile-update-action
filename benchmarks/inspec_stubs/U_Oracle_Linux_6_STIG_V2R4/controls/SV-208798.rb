control 'SV-208798' do
  title 'System security patches and updates must be installed and up-to-date.'
  desc 'Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.'
  desc 'check', "If the system is joined to Oracle's Unbreakable Linux Network or an internal YUM server that provides updates, invoking the following command will indicate if updates are available.: 

# yum check-update

If the system is not configured to update from one of these sources, run the following command to list when each package was last updated: 

$ rpm -qa -last

Compare this to (1) http://linux.oracle.com/errata/ and  (2) http://linux.oracle.com/cve/ to determine if the system is missing applicable security and bugfix updates.  If updates are not installed, this is a finding.  A ULN account is not required to obtain security updates Oracle also makes this content freely available on its Public YUM server at: http://public-yum.oracle.com/."
  desc 'fix', %q(If the system is joined to Oracle's Unbreakable Linux Network or an internal YUM server, run the following command to install updates

# yum update

If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from Oracle's Unbreakable Linux Network and installed using the "rpm" command.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9051r357374_chk'
  tag severity: 'medium'
  tag gid: 'V-208798'
  tag rid: 'SV-208798r603263_rule'
  tag stig_id: 'OL6-00-000011'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-9051r357375_fix'
  tag 'documentable'
  tag legacy: ['SV-64901', 'V-50695']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end

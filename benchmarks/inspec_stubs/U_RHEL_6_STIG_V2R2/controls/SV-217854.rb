control 'SV-217854' do
  title 'System security patches and updates must be installed and up-to-date.'
  desc 'Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.'
  desc 'check', 'If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available: 

# yum check-update

If the system is not configured to update from one of these sources, run the following command to list when each package was last updated: 

$ rpm -qa -last

Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine whether the system is missing applicable security and bugfix  updates. 
If updates are not installed, this is a finding.'
  desc 'fix', 'If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates: 

# yum update

If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using "rpm".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19335r376577_chk'
  tag severity: 'medium'
  tag gid: 'V-217854'
  tag rid: 'SV-217854r603264_rule'
  tag stig_id: 'RHEL-06-000011'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-19333r376578_fix'
  tag 'documentable'
  tag legacy: ['V-38481', 'SV-50281']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
